use std::ffi::OsString;
use std::fmt;
use std::ops::ControlFlow;
use std::path::Path;
use std::time::{Duration, SystemTime};

use coarsetime::Clock;
use hashbrown::HashMap;
use tracing::{debug, error, info, trace, warn};

use crate::{
    AppState,
    cache_layout::CacheLayout,
    cache_paths::CachePaths,
    cache_quota::accounted_size,
    cache_walk::{AnomalyLevel, DirFailure, EntryKind, WalkContext, WalkOutcome, Walker},
    config::Config,
    database::{MirrorEntry, OriginEntry},
    deb_mirror::{Mirror, MirrorKind, UriFormat as _},
    error::ErrorReport,
    humanfmt::HumanFmt,
    limits::RETENTION_TIME,
    log_once::Logged,
    metrics,
    sqlite_error::SqlxErrorReport,
};

use crate::cleanup::fetch::{DebnameKind, FetchFailure, fetch_packages};
use crate::cleanup::model::{
    ByHashUnit, CleanupUnit, FlatFetch, GroupOutcome, IndexSource, MetadataUnit, PartialsUnit,
    ReconcileFacet, ReconcileUnit, SkipReason, SweepAction, SweepReason, decide_sweep,
};
use crate::cleanup::packages::{KeyMapper, ReduceContext, ReduceError, reduce_file_list};
use crate::cleanup::partials::cleanup_tmp_dir;
use crate::cleanup::refs::{
    ByHashReferenceSet, active_origin_distributions, build_byhash_reference_set, byhash_dir_present,
};
use crate::cleanup::scan::{ScannedTree, remove_non_regular, scan_candidates};
use crate::cleanup::sweep::{SpanTable, sweep_aged_metadata, sweep_candidates};

/// Retention class of a scanned cache-tree entry, selecting its sweep span from
/// the `SpanTable`.
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

/// A cleanup unit abandoned on a cache-directory failure, which was logged
/// and counted where it happened (the carried [`Logged`] is the proof).
#[derive(Debug)]
pub(super) struct CleanupUnitError(pub(super) Logged);

/// One mirror's cleanup result.
pub(super) struct CleanupDone {
    pub(super) mirror: Mirror,
    pub(super) stats: UnitStats,
    /// Units of this mirror that did not do their whole job, each already
    /// logged.  A unit counts once however many of its entries failed.
    pub(super) failed_units: u64,
}

/// Cleanup counters, per sweep, unit, mirror or run.
///
/// Also the running tally threaded through a reconcile unit's resolvers, so
/// deletions performed before a mid-cascade group failure stay accounted (an
/// unaccounted deletion surfaces later as a spurious `Repaired cache size
/// discrepancy` warn).
#[derive(Clone, Copy, Default)]
pub(super) struct UnitStats {
    /// Entries considered.
    pub(super) scanned: u64,
    pub(super) removed: u64,
    pub(super) bytes_removed: u64,
    /// Subset of `removed` deleted as unreferenced-but-covered by-hash files.
    pub(super) removed_unreferenced: u64,
    /// Bytes of the regular files a `tmp/` reap unlinked (kept partials and
    /// foreign files). The quota counts them like cached files, so the
    /// reconcile subtracts them, but they are not cache evictions: kept out
    /// of `removed`/`bytes_removed` and the metrics fed from those.
    pub(super) tmp_bytes_removed: u64,
    /// Reconcile sweeps bailed for an incomplete reference set (an index that
    /// could not be fetched, parsed or looked up); the dashboard labels it as
    /// a failed step.
    pub(super) bailed: u64,
    /// Entries the unit left in place, or directories it left unread, on a
    /// cache I/O failure, each already logged and counted; the dashboard
    /// labels it as a failed step. A vanished entry is no failure.
    pub(super) io_failures: u64,
}

impl UnitStats {
    pub(super) const fn retained(&self) -> u64 {
        self.scanned.saturating_sub(self.removed)
    }

    /// Whether this unit left part of its job undone: a bailed sweep or an
    /// I/O failure it skipped past.
    const fn failed(&self) -> bool {
        self.bailed > 0 || self.io_failures > 0
    }

    /// The destructure makes a new counter a compile error here rather than a
    /// silently unsummed field.
    pub(super) fn accumulate(&mut self, unit: Self) {
        let Self {
            scanned,
            removed,
            bytes_removed,
            removed_unreferenced,
            tmp_bytes_removed,
            bailed,
            io_failures,
        } = unit;
        self.scanned += scanned;
        self.removed += removed;
        self.bytes_removed += bytes_removed;
        self.removed_unreferenced += removed_unreferenced;
        self.tmp_bytes_removed += tmp_bytes_removed;
        self.bailed += bailed;
        self.io_failures += io_failures;
    }

    /// Account one checksum-mismatch eviction performed during a reduce.
    pub(super) fn record_mismatch(&mut self, bytes: u64) {
        self.removed += 1;
        self.bytes_removed += accounted_size(bytes);
    }
}

/// Where to fetch a `Packages` index, how to name it, and how to map its
/// `Filename:` values onto scanned candidates.
struct FetchPlan<'a> {
    mirror: Mirror,
    // deb-owning mirror used to key `cache_metadata` invalidation on a
    // checksum-mismatch eviction. Differs from `mirror` for the flat-root and
    // strict-flat-pool fallbacks, where `mirror` is the (truncated)
    // Packages-fetch mirror while the candidate debs live under the original
    // sub-path mirror.
    owner_mirror: &'a Mirror,
    base_uri: String,
    // deb-cache layout for metadata invalidation; distinct from the fetched index's layout
    cache_layout: CacheLayout,
    debname: DebnameKind<'a>,
    keymap: KeyMapper<'a>,
}

/// Outcome of reducing the candidate set against one `Packages` index.
enum ReduceOutcome {
    /// Candidates remain.
    Reduced,
    /// No candidates remain.
    Exhausted,
    FetchFailed(FetchFailure),
}

/// Fetch one `Packages` index for `plan` and reduce `candidates` against it.
///
/// Any fetch failure (non-200, body-transfer failure, truncated body) is
/// `Ok(ReduceOutcome::FetchFailed(_))`. Only a reduce parse error propagates
/// as `Err`, unlogged - [`map_reduce`] logs it.
async fn reduce_against(
    plan: &FetchPlan<'_>,
    ctx: &ReconcileCtx<'_>,
    candidates: &mut HashMap<OsString, SpanClass>,
    tally: &mut UnitStats,
) -> Result<ReduceOutcome, ReduceError> {
    let &MirrorCtx {
        mirror: _,
        appstate,
        config,
        self_origins: _,
        now: _,
    } = ctx.mirror_ctx;

    let index = match fetch_packages(
        &plan.mirror,
        &plan.base_uri,
        &plan.debname,
        appstate,
        config.buffer_size,
    )
    .await
    {
        Ok(index) => index,
        Err(failure) => return Ok(ReduceOutcome::FetchFailed(failure)),
    };

    let mut reduce_ctx = ReduceContext {
        root: &ctx.unit.tree.root,
        mirror: plan.owner_mirror,
        layout: plan.cache_layout,
        tally,
        keymap: plan.keymap,
    };
    reduce_file_list(index, candidates, &mut reduce_ctx, config.buffer_size).await?;

    Ok(if candidates.is_empty() {
        ReduceOutcome::Exhausted
    } else {
        ReduceOutcome::Reduced
    })
}

/// Base URI of a flat repository's `Packages` index; the fetch cascade appends
/// each compression extension in turn.
fn flat_packages_base_uri(mirror: &Mirror) -> String {
    format!(
        "http://{}/{}/Packages",
        mirror.format_authority(),
        mirror.path()
    )
}

/// Build the `FetchPlan` for a flat-repo *root* `Packages` index, stripping the
/// in-mirror `prefix` (trailing `/`) from `Filename:` values so a root index
/// reconciles a sub-path mirror's cached debs.
fn flat_root_fetch_plan<'a>(mirror: &'a Mirror, seg: &str, prefix: &'a str) -> FetchPlan<'a> {
    let root_mirror = Mirror::new(
        mirror.host().clone(),
        mirror.port(),
        seg.into(),
        MirrorKind::Flat,
    );
    FetchPlan {
        base_uri: flat_packages_base_uri(&root_mirror),
        mirror: root_mirror,
        owner_mirror: mirror,
        cache_layout: CacheLayout::Flat,
        debname: DebnameKind::Flat,
        keymap: KeyMapper::RelpathUnderPrefix { prefix },
    }
}

/// Run every `unit` of one mirror in order. An abandoned unit does NOT abort
/// the remaining units for that mirror.
pub(super) async fn run_mirror_units(
    entry: MirrorEntry,
    units: Vec<CleanupUnit>,
    appstate: AppState,
    config: &'static Config,
) -> CleanupDone {
    let mirror: Mirror = entry.into();
    let now = SystemTime::now();

    // Read once for the structured-pool reconcile and the structured by-hash
    // completeness gate. A `MirrorKind::Flat` row emits neither unit, so it
    // never observes this `None`.
    let self_origins = if mirror.kind() == MirrorKind::Flat {
        None
    } else {
        read_self_origins(&appstate, &mirror).await
    };

    let ctx = MirrorCtx {
        mirror: &mirror,
        appstate: &appstate,
        config,
        self_origins: self_origins.as_deref(),
        now,
    };

    let mut totals = UnitStats::default();
    let mut failed_units = 0;

    for unit in &units {
        match run_unit(unit, &ctx).await {
            Ok(unit_stats) => {
                failed_units += u64::from(unit_stats.failed());
                totals.accumulate(unit_stats);
            }
            Err(CleanupUnitError(_logged @ Logged { .. })) => {
                failed_units += 1;
                debug!(
                    "Abandoned a cleanup unit for mirror {mirror}; continuing with the mirror's remaining units"
                );
            }
        }
    }

    CleanupDone {
        mirror,
        stats: totals,
        failed_units,
    }
}

/// Everything a unit needs that is fixed for the whole mirror.
struct MirrorCtx<'a> {
    mirror: &'a Mirror,
    appstate: &'a AppState,
    config: &'a Config,
    /// This mirror's own `origins` rows; `None` = unread (see
    /// [`read_self_origins`]).
    self_origins: Option<&'a [OriginEntry]>,
    /// One instant per mirror, so a single cycle ages every tree against the
    /// same `now`.
    now: SystemTime,
}

/// Read this mirror's own `origins` rows. `None` means the lookup failed
/// (logged here), and every consumer must treat it as *unknown*, never as
/// "this mirror has no origins": grace-sweeping on an unread origin set would
/// delete still-referenced debs.
async fn read_self_origins(appstate: &AppState, mirror: &Mirror) -> Option<Vec<OriginEntry>> {
    match appstate
        .database
        .get_origins_by_mirror(mirror.host(), mirror.port(), mirror.path())
        .await
    {
        Ok(origins) => Some(origins),
        Err(err) => {
            metrics::DB_OPERATION_FAILED.increment();
            error!(
                "Failed to look up origins for mirror {mirror}; treating its origin set as unknown for this cycle:  {}",
                SqlxErrorReport(&err)
            );
            None
        }
    }
}

struct ReconcileCtx<'a> {
    mirror_ctx: &'a MirrorCtx<'a>,
    unit: &'a ReconcileUnit,
}

/// Signal from a source-group resolver back to `run_reconcile_unit`.
enum GroupResolution {
    Ran(GroupOutcome),
    /// Reducing emptied the candidate map: short-circuit the whole
    /// unit — there is nothing left to sweep.
    Exhausted,
    /// The group's precondition did not hold (no candidates, no index to fetch),
    /// so it contributes no result; `decide_sweep` proceeds on the groups that
    /// did run (for an empty result set that is `Grace`).
    Skipped,
}

async fn run_unit(unit: &CleanupUnit, ctx: &MirrorCtx<'_>) -> Result<UnitStats, CleanupUnitError> {
    match unit {
        CleanupUnit::Reconcile(unit) => run_reconcile_unit(unit, ctx).await,
        CleanupUnit::ByHash(unit) => run_byhash_unit(unit, ctx).await,
        CleanupUnit::Metadata(unit) => Ok(run_metadata_unit(unit, ctx).await),
        CleanupUnit::Partials(unit) => Ok(run_partials_unit(unit, ctx).await),
    }
}

async fn run_partials_unit(unit: &PartialsUnit, ctx: &MirrorCtx<'_>) -> UnitStats {
    let mirror = ctx.mirror;

    let reaped = cleanup_tmp_dir(&ctx.config.cache_directory, &unit.root, ctx.now, unit.span).await;

    if reaped.entries > 0 {
        info!(
            "Removed {} stale tmp entries ({}) for mirror {mirror} in `{}`",
            reaped.entries,
            HumanFmt::Size(reaped.bytes),
            unit.root.display()
        );
    }

    UnitStats {
        tmp_bytes_removed: reaped.bytes,
        io_failures: reaped.io_failures,
        ..UnitStats::default()
    }
}

/// Age out stale index metadata. Runs before this mirror's by-hash units, so
/// a stale `Release` freed now unpins its digests this cycle.
async fn run_metadata_unit(unit: &MetadataUnit, ctx: &MirrorCtx<'_>) -> UnitStats {
    let mirror = ctx.mirror;

    debug!(
        "Sweeping aged index metadata for mirror {mirror} in `{}`",
        unit.root.display()
    );

    let swept = sweep_aged_metadata(&ctx.config.cache_directory, unit, ctx.now, mirror).await;

    if swept.removed > 0 {
        info!(
            "Removed {} stale index metadata files for mirror {mirror} ({})",
            swept.removed,
            HumanFmt::Size(swept.bytes_removed),
        );
    }

    // Only the removed files count as scanned: the unit retains nothing.
    UnitStats {
        scanned: swept.removed,
        ..swept
    }
}

/// Execute a [`ByHashUnit`]: probe the by-hash tree, build its `Release`
/// reference set, and sweep the leftovers.
async fn run_byhash_unit(
    unit: &ByHashUnit,
    ctx: &MirrorCtx<'_>,
) -> Result<UnitStats, CleanupUnitError> {
    let mirror = ctx.mirror;
    let layout = unit.layout;
    let cache_root = &ctx.config.cache_directory;

    // Skip the Release reads for a mirror without a by-hash tree (the common
    // case).
    if !byhash_dir_present(&unit.root).await? {
        return Ok(UnitStats::default());
    }

    // The on-disk `Release` set that defines "referenced" is the metadata
    // tree the by-hash directory sits in. Structured trees gate reference mode
    // on the complete active-origin distribution set (an unread origin set
    // forces age mode); flat trees have a single root Release.
    let release_layout = unit.release_layout();
    let expected_dists = if layout.is_flat() {
        Some(Vec::new())
    } else {
        active_origin_distributions(ctx.self_origins)
    };
    // `None` means age mode for the whole tree.
    let reference = match expected_dists {
        Some(expected_dists) => {
            let release_dir = CachePaths::new(cache_root).entry_dir(release_layout, mirror.site());
            build_byhash_reference_set(cache_root, &release_dir, layout, &expected_dists).await
        }
        None => None,
    };

    let stats = sweep_byhash_dir(
        cache_root,
        &unit.root,
        reference.as_ref(),
        unit.grace,
        unit.backstop,
        ctx.now,
        mirror,
        layout,
    )
    .await?;

    info!(
        "Removed {} files acquired by-hash for mirror {mirror} ({}; {} unreferenced, {} retained)",
        stats.removed,
        HumanFmt::Size(stats.bytes_removed),
        stats.removed_unreferenced,
        stats.retained(),
    );

    Ok(stats)
}

static BYHASH_WALK: WalkContext = WalkContext {
    what: "a by-hash directory",
    dir_failure: DirFailure::Abort("abandoning its cleanup this cycle"),
    entry_failure: "retaining it",
    non_regular: "removing it",
    anomalies: AnomalyLevel::Warn,
};

/// Walk one by-hash directory, classify each regular entry against `reference`,
/// and sweep the leftovers on a per-class span.
///
/// Referenced digests are kept forever; unreferenced-but-covered ones are
/// `ByHashCovered` (swept past `grace`, counted as `removed_unreferenced`);
/// anything uncovered, unclassifiable, or in age mode (`reference` is `None`)
/// is `ByHashUncovered` (swept past `backstop`). A non-regular entry is
/// unlinked without counting toward `removed` or the retained count: it was
/// never cached content.
///
/// The returned `scanned` is the kept count (referenced digests plus
/// candidates the sweep left in place) plus `removed`.
#[expect(
    clippy::too_many_arguments,
    reason = "single production call site; the tests drive each span and mode through it directly"
)]
async fn sweep_byhash_dir(
    cache_root: &Path,
    byhash_path: &Path,
    reference: Option<&ByHashReferenceSet>,
    grace: Duration,
    backstop: Duration,
    now: SystemTime,
    mirror: &Mirror,
    layout: CacheLayout,
) -> Result<UnitStats, CleanupUnitError> {
    let mut candidates: HashMap<OsString, SpanClass> = HashMap::new();
    let mut referenced_kept = 0u64;
    let mut io_failures = 0u64;

    let mut walker = Walker::below(cache_root, byhash_path, &BYHASH_WALK, ());

    while let Some(entry) = walker.next().await {
        match entry.kind() {
            EntryKind::NonRegular => {
                if !remove_non_regular(&entry.path()).await {
                    io_failures += 1;
                }
                continue;
            }
            EntryKind::Dir => {
                entry.report_unexpected("retaining it and excluding its contents from cleanup");
                continue;
            }
            EntryKind::File => {}
        }

        // A referenced digest never enters the candidate map: in a healthy
        // tree that is the bulk of the directory.
        let name = entry.name();
        let class = match reference.zip(name.to_str()) {
            Some((refset, digest)) => match refset.classify(digest) {
                Some((_algo, true)) => {
                    referenced_kept += 1;
                    continue;
                }
                Some((algo, false)) if refset.covers(algo) => SpanClass::ByHashCovered,
                Some(_) | None => SpanClass::ByHashUncovered,
            },
            // Age mode, or a name no `Release` digest could ever equal.
            None => SpanClass::ByHashUncovered,
        };

        candidates.insert(name.to_owned(), class);
    }

    io_failures += walker.io_failures();
    match walker.finish() {
        WalkOutcome::Complete | WalkOutcome::RootMissing => {}
        WalkOutcome::Aborted { logged, err: _ } => return Err(CleanupUnitError(logged)),
    }

    let survivors = candidates.len() as u64;
    let mut swept = sweep_candidates(
        byhash_path,
        &candidates,
        SpanTable {
            // No `Deb`-class candidates in a by-hash tree.
            deb: backstop,
            byhash_covered: grace,
            byhash_uncovered: backstop,
        },
        now,
        mirror,
        layout,
    )
    .await;

    // Referenced keeps + candidates the sweep left in place (too young / I/O
    // skipped); anomaly removals never count as retained.
    let retained = referenced_kept + survivors.saturating_sub(swept.removed);
    swept.scanned = retained + swept.removed;
    swept.io_failures += io_failures;
    Ok(swept)
}

/// Scan the tree, resolve each ordered [`IndexSource`] into a [`GroupOutcome`],
/// let [`decide_sweep`] pick the [`SweepAction`] from the unit's policy, and act
/// on it.
async fn run_reconcile_unit(
    unit: &ReconcileUnit,
    mirror_ctx: &MirrorCtx<'_>,
) -> Result<UnitStats, CleanupUnitError> {
    let layout = unit.facet.cache_layout();
    let policy = unit.policy;
    let &MirrorCtx {
        mirror,
        appstate: _,
        config,
        self_origins: _,
        now,
    } = mirror_ctx;

    let ScannedTree {
        candidates: mut cached_files,
        io_failures,
    } = scan_candidates(&config.cache_directory, &unit.tree, mirror.path()).await?;

    trace!("Cached files ({}): {cached_files:?}", cached_files.len());

    let mut tally = UnitStats {
        scanned: cached_files.len() as u64,
        io_failures,
        ..UnitStats::default()
    };

    // Nothing to reconcile, so no index source runs. From here on the map
    // only empties through a reduce, which returns `Exhausted` and ends the
    // unit, so every resolver below and the sweep see candidates.
    if cached_files.is_empty() {
        return Ok(tally);
    }

    let ctx = ReconcileCtx { mirror_ctx, unit };

    // A failed group must not end the loop: `decide_sweep` needs *all* groups
    // present (the flat cascade's decision depends on the always-last
    // co-located group appearing even when an earlier root/hybrid group
    // failed).
    let mut results: Vec<GroupOutcome> = Vec::with_capacity(unit.groups.len());
    // Set when an owning group (the hybrid archive-root reconcile) Completes:
    // its archive-root segment, for the strict-reconcile summary.
    let mut owning_root: Option<&str> = None;
    for group in &unit.groups {
        match resolve_group(&ctx, group, &mut cached_files, &mut tally).await {
            GroupResolution::Exhausted => return Ok(tally),
            GroupResolution::Skipped => {}
            GroupResolution::Ran(outcome) => {
                let complete = matches!(outcome, GroupOutcome::Complete);
                results.push(outcome);
                // An archive-root group that Completed owns the whole
                // reconciliation: stop resolving further groups and
                // grace-sweep the leftovers.
                if complete && let IndexSource::ArchiveRoot { root, prefix: _ } = group {
                    owning_root = Some(root);
                    break;
                }
            }
        }
    }

    let (spans, reason) = match decide_sweep(policy, &results) {
        SweepAction::Sweep { spans, reason } => (spans, reason),
        // The resolver already emitted the per-origin warn.
        SweepAction::Bail => {
            tally.bailed += 1;
            return Ok(tally);
        }
    };

    if let SweepReason::AgeFallback { primary } = &reason {
        warn!(
            "Failed to fetch the flat Packages index for mirror {mirror} ({primary}); falling back to time-based retention over {}",
            HumanFmt::Time(spans.deb)
        );
    }

    let swept = sweep_candidates(&unit.tree.root, &cached_files, spans, now, mirror, layout).await;

    match reason {
        SweepReason::AgeFallback { primary: _ } => info!(
            "Removed {} aged flat deb files for mirror {mirror} ({})",
            swept.removed,
            HumanFmt::Size(swept.bytes_removed)
        ),
        SweepReason::Grace => {
            if let Some(archive_root) = owning_root {
                info!(
                    "Strict-reconciled flat-pool mirror {mirror} against archive root `{archive_root}`: removed {} unreferenced deb files ({})",
                    swept.removed,
                    HumanFmt::Size(swept.bytes_removed)
                );
            } else {
                let flat = match unit.facet {
                    ReconcileFacet::StructuredPool => "",
                    ReconcileFacet::FlatTree => "flat ",
                };
                info!(
                    "Removed {} unreferenced {flat}deb files for mirror {mirror} ({})",
                    swept.removed,
                    HumanFmt::Size(swept.bytes_removed)
                );
            }
        }
    }
    tally.accumulate(swept);

    Ok(tally)
}

async fn resolve_group(
    ctx: &ReconcileCtx<'_>,
    group: &IndexSource,
    cached_files: &mut HashMap<OsString, SpanClass>,
    tally: &mut UnitStats,
) -> GroupResolution {
    match group {
        IndexSource::SelfOrigins => resolve_origin_packages_self(ctx, cached_files, tally).await,
        IndexSource::ArchiveRoot { root, prefix } => {
            resolve_origin_packages_archive_root(ctx, root, prefix, cached_files, tally).await
        }
        IndexSource::FlatPackages {
            fetch: FlatFetch::Colocated,
        } => resolve_flat_colocated(ctx, cached_files, tally).await,
        IndexSource::FlatPackages {
            fetch: FlatFetch::RootSegment { seg, prefix },
        } => resolve_flat_root_segment(ctx, seg, prefix, cached_files, tally).await,
    }
}

/// The `mirrors_v2` row gate for the resolvers whose referencing index
/// belongs to *another* row (the archive root, the flat-repo root): cleanup
/// never mints a row, so the group runs only when that row exists.
/// `Ok(())` proceeds; `Err` is the group's resolution.
async fn gate_on_row(
    ctx: &ReconcileCtx<'_>,
    seg: &str,
    noun: &'static str,
) -> Result<(), GroupResolution> {
    let (mirror, appstate) = (ctx.mirror_ctx.mirror, ctx.mirror_ctx.appstate);
    match appstate
        .database
        .mirror_exists(mirror.host(), mirror.port(), seg)
        .await
    {
        Ok(true) => Ok(()),
        Ok(false) => Err(GroupResolution::Ran(GroupOutcome::NotApplicable(
            SkipReason::NoReferenceSet,
        ))),
        Err(err) => {
            metrics::DB_OPERATION_FAILED.increment();
            error!(
                "Failed to check the mirror row of {noun} `{seg}`; continuing with the mirror's remaining index sources:  {}",
                SqlxErrorReport(&err)
            );
            Err(GroupResolution::Ran(GroupOutcome::NotApplicable(
                SkipReason::DbError,
            )))
        }
    }
}

/// The fetch plan for one active origin's `dists/.../Packages*` index.
/// `fetch_mirror` is the row the index is fetched through (the mirror itself,
/// or its archive root); `owner_mirror` is where the candidate debs live.
fn origin_fetch_plan<'a>(
    fetch_mirror: &Mirror,
    owner_mirror: &'a Mirror,
    origin: &'a OriginEntry,
    cache_layout: CacheLayout,
    keymap: KeyMapper<'a>,
) -> FetchPlan<'a> {
    FetchPlan {
        mirror: fetch_mirror.clone(),
        owner_mirror,
        base_uri: origin.uri(),
        cache_layout,
        debname: DebnameKind::OriginScoped {
            distribution: &origin.distribution,
            component: &origin.component,
            architecture: &origin.architecture,
        },
        keymap,
    }
}

/// Map a [`reduce_against`] outcome onto a group's resolution: `Continue`
/// means the index reduced and the resolver carries on; `Break` carries the
/// group's resolution.  A fetch failure is handed to `on_fetch_failed` for
/// the resolver's own diagnostic; a reduce error is logged here.
fn map_reduce(
    result: Result<ReduceOutcome, ReduceError>,
    mirror: &Mirror,
    index: fmt::Arguments<'_>,
    parse_consequence: &'static str,
    on_fetch_failed: impl FnOnce(&FetchFailure),
) -> ControlFlow<GroupResolution> {
    match result {
        Ok(ReduceOutcome::Reduced) => ControlFlow::Continue(()),
        Ok(ReduceOutcome::Exhausted) => {
            debug!(
                "Every cached deb file of mirror {mirror} is referenced by {index}; skipping the remaining index sources and the sweep"
            );
            ControlFlow::Break(GroupResolution::Exhausted)
        }
        Ok(ReduceOutcome::FetchFailed(failure)) => {
            on_fetch_failed(&failure);
            ControlFlow::Break(GroupResolution::Ran(GroupOutcome::FetchFailed(failure)))
        }
        Err(err) => {
            error!(
                "Failed to reduce {index} for mirror {mirror}; {parse_consequence}:  {}",
                ErrorReport(&err)
            );
            ControlFlow::Break(GroupResolution::Ran(GroupOutcome::ParseError))
        }
    }
}

/// Hybrid flat-pool source resolver (issue #162, e.g. Gitea/Forgejo
/// `.../pool/<dist>/<comp>`). The referencing `Packages` index lives in the
/// structured `dists/` tree of the flat repo's *archive root*, so this
/// reconciles the sub-path mirror's cached debs against the archive-root
/// row's active origins, stripping the in-mirror `prefix` from `Filename:`
/// values. This is the unit's owning group: on `Complete` the remaining
/// root/colocated groups are skipped; on any failure the cascade continues.
async fn resolve_origin_packages_archive_root(
    ctx: &ReconcileCtx<'_>,
    root: &str,
    prefix: &str,
    cached_files: &mut HashMap<OsString, SpanClass>,
    tally: &mut UnitStats,
) -> GroupResolution {
    let (mirror, appstate) = (ctx.mirror_ctx.mirror, ctx.mirror_ctx.appstate);

    if let Err(resolution) = gate_on_row(ctx, root, "archive root").await {
        return resolution;
    }

    let origins = match appstate
        .database
        .get_origins_by_mirror(mirror.host(), mirror.port(), root)
        .await
    {
        Ok(o) => o,
        Err(err) => {
            metrics::DB_OPERATION_FAILED.increment();
            error!(
                "Failed to look up the origins of archive root `{root}`; continuing with the mirror's remaining index sources:  {}",
                SqlxErrorReport(&err)
            );
            return GroupResolution::Ran(GroupOutcome::NotApplicable(SkipReason::DbError));
        }
    };

    let now: Duration = Clock::now_since_epoch().into();
    let active_origins: Vec<_> = origins
        .into_iter()
        .filter(|origin| origin.is_active(now))
        .collect();

    if active_origins.is_empty() {
        return GroupResolution::Ran(GroupOutcome::NotApplicable(SkipReason::NoReferenceSet));
    }

    let archive_mirror = Mirror::new(
        mirror.host().clone(),
        mirror.port(),
        root.into(),
        MirrorKind::Structured,
    );

    let keymap = KeyMapper::RelpathUnderPrefix { prefix };
    for origin in &active_origins {
        let plan = origin_fetch_plan(&archive_mirror, mirror, origin, CacheLayout::Flat, keymap);
        let step = map_reduce(
            reduce_against(&plan, ctx, cached_files, tally).await,
            mirror,
            format_args!("the archive-root Packages index `{root}`"),
            "continuing with the mirror's remaining index sources",
            |status| {
                debug!(
                    "Failed to fetch the archive-root Packages index for `{root}` ({status}); continuing with fallback index sources for mirror {mirror}"
                );
            },
        );
        if let ControlFlow::Break(resolution) = step {
            return resolution;
        }
    }

    GroupResolution::Ran(GroupOutcome::Complete)
}

/// Flat root-segment source resolver: a flat sub-path mirror (e.g.
/// `apt/amd64`) whose `Packages` index lives at its registered flat-repo root
/// (`apt/`). Never owning: a complete root reference set still lets the
/// always-last co-located group run unless the reduce exhausts the map.
async fn resolve_flat_root_segment(
    ctx: &ReconcileCtx<'_>,
    seg: &str,
    prefix: &str,
    cached_files: &mut HashMap<OsString, SpanClass>,
    tally: &mut UnitStats,
) -> GroupResolution {
    let mirror = ctx.mirror_ctx.mirror;

    if let Err(resolution) = gate_on_row(ctx, seg, "flat-repo root").await {
        return resolution;
    }

    let plan = flat_root_fetch_plan(mirror, seg, prefix);
    // A fetch failure is silent here: the co-located probe still runs, and
    // `run_reconcile_unit`'s age-fallback warn reports that one's status.
    match map_reduce(
        reduce_against(&plan, ctx, cached_files, tally).await,
        mirror,
        format_args!("the flat-root Packages index `{seg}`"),
        "falling back to time-based retention",
        |_status| {},
    ) {
        ControlFlow::Continue(()) => GroupResolution::Ran(GroupOutcome::Complete),
        ControlFlow::Break(resolution) => resolution,
    }
}

/// Co-located flat source resolver: the always-last group, reconciling the
/// mirror's own debs against its `<mirror.path>/Packages*` index.
/// `decide_sweep` reads this group's outcome to pick grace vs age fallback.
async fn resolve_flat_colocated(
    ctx: &ReconcileCtx<'_>,
    cached_files: &mut HashMap<OsString, SpanClass>,
    tally: &mut UnitStats,
) -> GroupResolution {
    let mirror = ctx.mirror_ctx.mirror;

    let plan = FetchPlan {
        mirror: mirror.clone(),
        owner_mirror: mirror,
        base_uri: flat_packages_base_uri(mirror),
        cache_layout: CacheLayout::Flat,
        debname: DebnameKind::Flat,
        keymap: KeyMapper::Relpath,
    };
    // A fetch failure is silent here: `run_reconcile_unit`'s age-fallback
    // warn reports the co-located status.
    match map_reduce(
        reduce_against(&plan, ctx, cached_files, tally).await,
        mirror,
        format_args!("the co-located flat Packages index"),
        "falling back to time-based retention",
        |_status| {},
    ) {
        ControlFlow::Continue(()) => GroupResolution::Ran(GroupOutcome::Complete),
        ControlFlow::Break(resolution) => resolution,
    }
}

/// Structured-pool source resolver: reduces the candidate map against each
/// active origin's `dists/.../Packages*`.
async fn resolve_origin_packages_self(
    ctx: &ReconcileCtx<'_>,
    cached_files: &mut HashMap<OsString, SpanClass>,
    tally: &mut UnitStats,
) -> GroupResolution {
    let policy = ctx.unit.policy;
    let &MirrorCtx {
        mirror,
        appstate: _,
        config: _,
        self_origins,
        now: _,
    } = ctx.mirror_ctx;

    // Used only for the diagnostics below.
    let grace = policy.grace();

    let Some(origins) = self_origins else {
        // The origins read failed (logged at the read site). `DbError` bails
        // the unit -- treating it as "no origins" would grace-sweep files we
        // never got to check.
        return GroupResolution::Ran(GroupOutcome::NotApplicable(SkipReason::DbError));
    };

    trace!("Origins ({}): {origins:?}", origins.len());

    let now: Duration = Clock::now_since_epoch().into();

    let origins_count = origins.len();

    let active_origins = origins
        .iter()
        .filter(|origin| origin.is_active(now))
        .collect::<Vec<_>>();

    info!(
        "Found {} active origins and {} cached deb files for mirror {mirror} (`{}`)",
        active_origins.len(),
        cached_files.len(),
        mirror.site(),
    );

    // Disambiguate "no recent .deb traffic" (origins present but stale) from
    // "origins never recorded".
    if active_origins.is_empty() {
        if origins_count == 0 {
            info!(
                "Mirror {mirror}: no origin records, so cached debs cannot be reconciled against any Packages index; aging them out via the {} grace window",
                HumanFmt::Time(grace),
            );
        } else {
            let most_recent_origin: i64 = origins.iter().map(|o| o.last_seen).max().unwrap_or(0);
            let now_secs = i64::try_from(now.as_secs()).unwrap_or(i64::MAX);
            let age_secs = u64::try_from(now_secs.saturating_sub(most_recent_origin)).unwrap_or(0);
            let most_recent_age = Duration::from_secs(age_secs);
            info!(
                "Mirror {mirror}: all {origins_count} origin records stale (most recent seen {} ago, retention window {}); cached debs will age out via the {} grace window",
                HumanFmt::Time(most_recent_age),
                HumanFmt::Time(RETENTION_TIME),
                HumanFmt::Time(grace),
            );
        }
        // `decide_sweep` on the resulting empty result set returns `Grace`.
        return GroupResolution::Skipped;
    }

    for origin in active_origins {
        let plan = origin_fetch_plan(
            mirror,
            mirror,
            origin,
            CacheLayout::StructuredPool,
            KeyMapper::Basename,
        );
        // A missing Packages file leaves the reference set incomplete;
        // deleting now risks wiping files referenced only by this origin
        // (typical when a distribution goes EOL upstream), so the unit bails.
        let step = map_reduce(
            reduce_against(&plan, ctx, cached_files, tally).await,
            mirror,
            format_args!("the Packages index"),
            "skipping cleanup for this mirror",
            |status| {
                warn!(
                    "Failed to fetch the Packages index for host {} path {} ({status}); skipping cleanup for mirror {mirror}",
                    origin.host, origin.mirror_path
                );
            },
        );
        if let ControlFlow::Break(resolution) = step {
            return resolution;
        }
    }

    GroupResolution::Ran(GroupOutcome::Complete)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ClientHost;
    use crate::test_support::structured_mirror;

    #[test]
    fn flat_root_fetch_plan_keys_metadata_by_owner_mirror() {
        // `Mirror` equality includes path + kind, so an invalidation keyed by
        // the root fetch mirror could never match the stored entry.
        let owner = Mirror::new(
            ClientHost::new("deb.example.com").expect("valid host"),
            None,
            "apt/amd64".into(),
            MirrorKind::Flat,
        );
        let plan = flat_root_fetch_plan(&owner, "apt", "amd64/");
        assert_eq!(plan.owner_mirror, &owner);
        assert_eq!(plan.owner_mirror.path(), "apt/amd64");
        assert_ne!(plan.mirror, owner);
        assert_eq!(plan.mirror.path(), "apt");
    }

    // --- by-hash sweep, with an injected `now` (birthtime is not backdatable
    //     on Linux) and an explicitly-built reference set.

    use hashbrown::HashSet;

    use crate::deb_mirror::MirrorKind;
    use crate::index_parser::hex_encode;

    const DAY: u64 = 24 * 60 * 60;

    /// Sweep the by-hash directory `dir` with a 3-day grace and a 90-day
    /// backstop.
    async fn sweep(
        dir: &Path,
        reference: Option<&ByHashReferenceSet>,
        now: SystemTime,
    ) -> UnitStats {
        sweep_byhash_dir(
            dir,
            dir,
            reference,
            Duration::from_secs(3 * DAY),
            Duration::from_secs(90 * DAY),
            now,
            &structured_mirror("deb.example.org", "debian"),
            CacheLayout::DistsByHash,
        )
        .await
        .expect("sweep ok")
    }

    /// A reference set covering SHA256 only, referencing `digest`.
    fn sha256_only(digest: [u8; 32]) -> ByHashReferenceSet {
        ByHashReferenceSet {
            sha256: HashSet::from_iter([digest]),
            sha512: HashSet::new(),
            complete_sha256: true,
            complete_sha512: false,
        }
    }

    #[tokio::test]
    async fn cleanup_reference_mode_removes_unreferenced_after_grace() {
        let dir = tempfile::tempdir().expect("tempdir");
        let referenced = [0x01u8; 32];
        let unref_a = [0x02u8; 32];
        let unref_b = [0x03u8; 32];
        for d in [&referenced, &unref_a, &unref_b] {
            std::fs::write(dir.path().join(hex_encode(d)), b"index-bytes").expect("write");
        }
        let set = sha256_only(referenced);

        let now = SystemTime::now() + Duration::from_secs(10 * DAY);
        let outcome = sweep(dir.path(), Some(&set), now).await;

        assert_eq!(outcome.retained(), 1);
        assert_eq!(outcome.removed, 2);
        assert_eq!(outcome.removed_unreferenced, 2);
        assert!(dir.path().join(hex_encode(&referenced)).exists());
        assert!(!dir.path().join(hex_encode(&unref_a)).exists());
    }

    #[tokio::test]
    async fn malformed_release_section_uses_age_retention_for_omitted_digests() {
        let releases = tempfile::tempdir().expect("Release directory");
        let files = tempfile::tempdir().expect("by-hash directory");
        let first = hex_encode(&[0x11; 32]);
        let unindented = hex_encode(&[0x22; 32]);
        let following = hex_encode(&[0x33; 32]);
        std::fs::write(
            releases.path().join("stable_Release"),
            format!("SHA256:\n {first} 1 Packages\n"),
        )
        .expect("valid sibling Release");
        for boundary in [
            format!("{unindented} 1 second/Packages"),
            "-broken: value".to_owned(),
            "#broken: value".to_owned(),
        ] {
            std::fs::write(
                releases.path().join("sid_Release"),
                format!("SHA256:\n {first} 1 first/Packages\n{boundary}\n {following} 1 third/Packages\n"),
            )
            .expect("malformed Release");
            for digest in [&unindented, &following] {
                std::fs::write(files.path().join(digest), b"x").expect("cached index");
            }
            let references = build_byhash_reference_set(
                releases.path(),
                releases.path(),
                CacheLayout::DistsByHash,
                &["stable", "sid"],
            )
            .await;
            assert!(references.is_none(), "malformed references force age mode");

            let now = SystemTime::now();
            for (age_days, expected_removed) in [(10, 0), (91, 2)] {
                let outcome = sweep(
                    files.path(),
                    references.as_ref(),
                    now + Duration::from_secs(age_days * DAY),
                )
                .await;
                assert_eq!(outcome.removed, expected_removed);
                assert_eq!(outcome.removed_unreferenced, 0);
                for digest in [&unindented, &following] {
                    assert_eq!(files.path().join(digest).exists(), age_days < 90);
                }
            }
        }
    }

    #[tokio::test]
    async fn byhash_sweep_does_not_count_a_removed_symlink_as_eviction() {
        let dir = tempfile::tempdir().expect("tempdir");
        let link = dir.path().join(hex_encode(&[0x0au8; 32]));
        std::os::unix::fs::symlink("/nonexistent", &link).expect("symlink");

        let outcome = sweep(dir.path(), None, SystemTime::now()).await;

        assert!(link.symlink_metadata().is_err(), "the symlink is unlinked");
        assert_eq!(outcome.removed, 0);
        assert_eq!(outcome.retained(), 0);
    }

    #[tokio::test]
    async fn cleanup_reference_mode_grace_keeps_recent() {
        let dir = tempfile::tempdir().expect("tempdir");
        let unref = [0x07u8; 32];
        std::fs::write(dir.path().join(hex_encode(&unref)), b"x").expect("write");
        // An unrelated referenced digest: the grace path needs the algo
        // covered.
        let set = sha256_only([0x09u8; 32]);

        let now = SystemTime::now() + Duration::from_secs(DAY);
        let outcome = sweep(dir.path(), Some(&set), now).await;

        assert_eq!(outcome.retained(), 1);
        assert_eq!(outcome.removed, 0);
        assert!(dir.path().join(hex_encode(&unref)).exists());
    }

    #[tokio::test]
    async fn cleanup_fallback_age_mode() {
        let dir = tempfile::tempdir().expect("tempdir");
        for d in [[0x21u8; 32], [0x22u8; 32]] {
            std::fs::write(dir.path().join(hex_encode(&d)), b"x").expect("write");
        }
        let now = SystemTime::now();

        let young = now + Duration::from_secs(DAY);
        let outcome = sweep(dir.path(), None, young).await;
        assert_eq!(outcome.removed, 0);
        assert_eq!(outcome.retained(), 2);

        let old = now + Duration::from_secs(91 * DAY);
        let outcome = sweep(dir.path(), None, old).await;
        assert_eq!(outcome.removed, 2);
        assert_eq!(outcome.removed_unreferenced, 0);
    }
}
