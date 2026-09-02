use std::ffi::OsString;
use std::fmt;
use std::ops::ControlFlow;
use std::path::Path;
use std::time::{Duration, SystemTime};

use coarsetime::Clock;
use hashbrown::HashMap;
use tracing::{debug, error, info, trace, warn};

use crate::{
    AppState, RETENTION_TIME,
    cache_layout::CacheLayout,
    cache_walk::{DirFailure, EntryKind, OnMissing, WalkContext, WalkOutcome, Walker},
    config::Config,
    database::{MirrorEntry, OriginEntry},
    deb_mirror::{Mirror, MirrorKind, UriFormat as _},
    error::ErrorReport,
    humanfmt::HumanFmt,
    metrics,
    utils::Logged,
};

use http::{StatusCode, header::CONTENT_LENGTH};

use crate::cleanup::model::{
    ByHashUnit, CleanupUnit, DistGate, FlatFetch, GroupOutcome, GroupResult, IndexSource,
    KeymapSpec, MetadataUnit, OriginOwner, PartialsUnit, ReconcileFacet, ReconcilePolicy,
    ReconcileUnit, SkipReason, SourceGroup, SweepAction, SweepReason, decide_sweep,
};
use crate::cleanup::packages::{
    DebnameKind, FetchFailure, KeyMapper, PackagesLayout, ReduceContext, ReduceError,
    body_is_incomplete, packages_body_to_memfd, reduce_file_list, try_fetch_packages_file,
};
use crate::cleanup::partials::cleanup_tmp_dir;
use crate::cleanup::refs::{
    ByHashReferenceSet, active_origin_distributions, build_byhash_reference_set, byhash_dir_present,
};
use crate::cleanup::scan::{remove_non_regular, scan_candidates};
use crate::cleanup::sweep::{SpanTable, SweepResult, sweep_aged_metadata, sweep_candidates};

/// Retention class of a scanned cache-tree entry, selecting its sweep span from
/// the `SpanTable`.
///
/// Candidates live in a `HashMap<OsString, SpanClass>` keyed by the entry's path
/// *relative to the unit's tree root*: produced by
/// [`scan_candidates`], reduced by the
/// index sources (which match that key against a `Filename:` value), and swept
/// by [`sweep_candidates`], which
/// rejoins it onto the root. Storing the full path per entry instead would cost
/// megabytes on a large mirror for no lookup the key cannot already serve.
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

/// A cleanup unit abandoned on a cache-directory failure.
///
/// The failure was logged - with its path, verb and consequence - and counted
/// (`CACHE_IO_FAILURE`) where it happened: the walker's one directory-failure
/// line (`cache_walk::WalkContext::dir_failure`, `DirFailure::Abort`).  The
/// carried [`Logged`] is the proof, so every arm this passes through
/// (`run_reconcile_unit`, `run_byhash_unit`, `run_mirror_units`) maps it
/// silently; there is exactly one line per abandoned unit.
#[derive(Debug)]
pub(super) struct CleanupUnitError(pub(super) Logged);

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
///
/// Also the running tally threaded through a reconcile unit's resolvers, so
/// deletions performed before a mid-cascade group failure stay accounted (an
/// unaccounted deletion surfaces later as a spurious `Repaired cache size
/// discrepancy` warn).
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

impl UnitStats {
    /// Fold one sweep's counters in. The reconcile facets
    /// (`StructuredPool`/`FlatTree`) only sweep `Deb`-class candidates, so
    /// `removed_unreferenced` stays zero there; the by-hash facets thread it
    /// through their own path.
    pub(super) fn fold(&mut self, swept: SweepResult) {
        self.removed += swept.files_removed;
        self.bytes_removed += swept.bytes_removed;
        self.removed_unreferenced += swept.removed_unreferenced;
    }

    /// Account one checksum-mismatch eviction performed during a reduce.
    pub(super) fn record_mismatch(&mut self, bytes: u64) {
        self.removed += 1;
        self.bytes_removed += bytes;
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

/// Fetch one `Packages` index for `plan`, buffer it, and reduce `candidates`
/// against it (verifying matched cache files and evicting genuine
/// checksum mismatches, whose removals fold straight into `tally`).
///
/// A *fetch miss* (non-200), a *body-transfer failure* (upstream read timeout,
/// rate abort, memfd/IO buffer error), or a *silently-truncated body* (the 200
/// header arrived but the download aborted mid-stream, leaving fewer bytes than
/// the announced `Content-Length`) all yield `Ok(ReduceOutcome::FetchFailed(_))`
/// so the caller can bail the mirror conservatively. Only a *reduce parse error*
/// (decompression bomb, malformed or zero-byte compressed index, local read
/// failure) propagates as `Err`, unlogged - [`map_reduce`] logs it once with
/// the resolver's consequence; every caller treats it conservatively too.
pub(super) async fn reduce_against(
    plan: &FetchPlan<'_>,
    root: &Path,
    candidates: &mut HashMap<OsString, SpanClass>,
    tally: &mut UnitStats,
    appstate: &AppState,
    config: &Config,
) -> Result<ReduceOutcome, ReduceError> {
    let (mut response, pkgfmt) = match try_fetch_packages_file(
        &plan.mirror,
        &plan.base_uri,
        plan.layout,
        &plan.debname,
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
            "Packages index `{memfdname}` truncated (announced {}, buffered {written}); treating as fetch failure",
            announced.unwrap_or(0)
        );
        return Ok(ReduceOutcome::FetchFailed(FetchFailure {
            status: StatusCode::BAD_GATEWAY,
            upstream: None,
        }));
    }

    let mut ctx = ReduceContext {
        root,
        mirror: &plan.owner_mirror,
        layout: plan.cache_layout,
        tally,
        keymap: &plan.keymap,
    };
    reduce_file_list(pkgfmt, file, &memfdname, candidates, &mut ctx, config).await?;

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
/// single per-mirror [`CleanupDone`]. An abandoned unit ([`CleanupUnitError`],
/// already logged where it failed) does NOT abort the remaining units for
/// that mirror.
pub(super) async fn run_mirror_units(
    entry: MirrorEntry,
    units: Vec<CleanupUnit>,
    appstate: AppState,
    config: &'static Config,
) -> CleanupDone {
    let mirror: Mirror = entry.clone().into();
    let now = SystemTime::now();

    // The mirror's own `origins` rows, read once: the structured-pool reconcile
    // and the structured by-hash completeness gate both reconcile against them
    // and used to issue this identical query one apiece. A `MirrorKind::Flat`
    // row emits neither unit, so it still issues none -- and never observes the
    // `None` that a failed read would produce.
    let self_origins = if entry.kind() == MirrorKind::Flat {
        None
    } else {
        read_self_origins(&appstate, &mirror, &entry).await
    };

    let ctx = MirrorCtx {
        mirror: &mirror,
        entry: &entry,
        appstate: &appstate,
        config,
        self_origins: self_origins.as_deref(),
        now,
    };

    let mut scanned = 0u64;
    let mut removed = 0u64;
    let mut bytes_removed = 0u64;
    let mut removed_unreferenced = 0u64;

    for unit in &units {
        match run_unit(unit, &ctx).await {
            Ok(unit_stats) => {
                scanned += unit_stats.scanned;
                removed += unit_stats.removed;
                bytes_removed += unit_stats.bytes_removed;
                removed_unreferenced += unit_stats.removed_unreferenced;
            }
            Err(CleanupUnitError(_logged @ Logged { .. })) => {
                debug!(
                    "Abandoned a cleanup unit for mirror {mirror}; continuing with the mirror's remaining units"
                );
            }
        }
    }

    CleanupDone::tally(
        mirror,
        scanned,
        removed,
        bytes_removed,
        removed_unreferenced,
    )
}

/// Everything a unit needs that is fixed for the whole mirror: its identity, the
/// DB/config handles, the once-per-cycle origins read, and the single reference
/// instant every one of its trees is aged against.
struct MirrorCtx<'a> {
    mirror: &'a Mirror,
    entry: &'a MirrorEntry,
    appstate: &'a AppState,
    config: &'a Config,
    /// This mirror's own `origins` rows; `None` = unread (see
    /// [`read_self_origins`]).
    self_origins: Option<&'a [OriginEntry]>,
    /// One instant per mirror, so a single cycle ages every tree against the
    /// same `now` (and so the by-hash / metadata deletion paths are testable,
    /// birthtime not being backdatable on Linux).
    now: SystemTime,
}

/// Read this mirror's own `origins` rows. `None` means the lookup failed --
/// logged and counted here, once, rather than at each consumer -- and every
/// consumer must treat it as *unknown*, never as "this mirror has no origins":
/// grace-sweeping on an unread origin set would delete still-referenced debs.
async fn read_self_origins(
    appstate: &AppState,
    mirror: &Mirror,
    entry: &MirrorEntry,
) -> Option<Vec<OriginEntry>> {
    match appstate
        .database
        .get_origins_by_mirror(&entry.host, entry.port(), &entry.path)
        .await
    {
        Ok(origins) => Some(origins),
        Err(err) => {
            metrics::DB_OPERATION_FAILED.increment();
            error!(
                "Failed to look up origins for mirror {mirror}; treating its origin set as unknown for this cycle:  {}",
                ErrorReport(&err)
            );
            None
        }
    }
}

/// Immutable context threaded through the reconcile-unit resolvers (the
/// candidate map and tally are the only mutable state, kept separate).
struct ReconcileCtx<'a> {
    policy: ReconcilePolicy,
    /// This mirror's own `origins` rows, read once per cycle by
    /// [`run_mirror_units`]; `None` = unread (see [`read_self_origins`]).
    self_origins: Option<&'a [OriginEntry]>,
    /// The unit's tree root: candidate keys are relative to it, so a resolver
    /// needs it to turn a matched key back into an on-disk path. Named apart
    /// from the archive-root / flat-root *segments* the resolvers call `root`.
    tree_root: &'a Path,
    mirror: &'a Mirror,
    entry: &'a MirrorEntry,
    appstate: &'a AppState,
    config: &'a Config,
}

/// Signal from a source-group resolver back to the generic tail.
///
/// A resolver reports only *what happened*; the tail stamps the `owning` /
/// `root_seg` context back on from the [`SourceGroup`] it dispatched, so those
/// two can never drift from the classifier's emission.
enum GroupResolution {
    /// The group ran with this outcome (pushed onto the tail's results).
    Ran(GroupOutcome),
    /// Reducing emptied the candidate map: short-circuit the whole
    /// unit — there is nothing left to sweep.
    Exhausted,
    /// The group's precondition did not hold (no candidates, no index to fetch),
    /// so it contributes no result; `decide_sweep` proceeds on the groups that
    /// did run (for an empty result set that is `Grace`).
    Skipped,
}

/// Execute one [`CleanupUnit`]: hand each variant's payload to the arm that
/// consumes it. The dispatch is the whole of it — every arm's signature names
/// exactly the inputs that shape carries, so there is no facet -> layout table
/// to drift from the roots the classifier built and no policy-shape guard to
/// fall through.
async fn run_unit(unit: &CleanupUnit, ctx: &MirrorCtx<'_>) -> Result<UnitStats, CleanupUnitError> {
    match unit {
        CleanupUnit::Reconcile(unit) => run_reconcile_unit(unit, ctx).await,
        CleanupUnit::ByHash(unit) => run_byhash_unit(unit, ctx).await,
        CleanupUnit::Metadata(unit) => Ok(run_metadata_unit(unit, ctx).await),
        CleanupUnit::Partials(unit) => Ok(run_partials_unit(unit, ctx).await),
    }
}

/// Reap one [`PartialsUnit`]'s `tmp/` directory (the classifier emits one for
/// the structured tree, one for the flat tree — see `model::classify_mirror`).
///
/// Delegates to [`cleanup_tmp_dir`] for the actual sweep and logs
/// the same summary line `cleanup_stale_partials` used to emit (formerly
/// aggregated across every mirror in one pre-pass; now per-unit). The count is
/// deliberately NOT returned in `UnitStats` — partial-download
/// scratch files are not cached content, so they must not inflate
/// `CLEANUP_EVICTIONS`/`CLEANUP_BYTES_RECLAIMED` or the quota reconcile, exactly
/// matching the old pre-pass, which only ever logged its total.
async fn run_partials_unit(unit: &PartialsUnit, ctx: &MirrorCtx<'_>) -> UnitStats {
    let mirror = ctx.mirror;

    let removed = cleanup_tmp_dir(&unit.root, ctx.now, unit.span).await;

    if removed > 0 {
        info!(
            "Removed {removed} stale tmp entries for mirror {mirror} in `{}`",
            unit.root.display()
        );
    }

    UnitStats::default()
}

/// Age out stale index metadata for a [`MetadataUnit`]: a direct
/// [`sweep_aged_metadata`] over the unit's root. Structured
/// (`CacheLayout::Dists`) sweeps the pure `dists/` metadata tree; flat
/// (`CacheLayout::Flat`) sweeps the flat root, leaving co-mingled `.deb` files
/// to the flat-deb cleanup. The summary line is
/// emitted only when something was removed; the metadata units contribute nothing to `files_retained` (their
/// `scanned` equals `removed`, so the derived retained count is zero).
///
/// The always-fired debug marker documents the unit ordering: the metadata sweep runs
/// (and logs) before this mirror's by-hash units in the same cycle, so a stale
/// `Release` freed now unpins its digests this cycle.
async fn run_metadata_unit(unit: &MetadataUnit, ctx: &MirrorCtx<'_>) -> UnitStats {
    let mirror = ctx.mirror;

    debug!(
        "Sweeping aged index metadata for mirror {mirror} in `{}`",
        unit.root.display()
    );

    let swept = sweep_aged_metadata(&unit.root, unit.span, ctx.now, mirror, unit.layout).await;

    if swept.files_removed > 0 {
        info!(
            "Removed {} stale index metadata files for mirror {mirror} ({})",
            swept.files_removed,
            HumanFmt::Size(swept.bytes_removed),
        );
    }

    UnitStats {
        scanned: swept.files_removed,
        removed: swept.files_removed,
        bytes_removed: swept.bytes_removed,
        removed_unreferenced: 0,
    }
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

/// Execute a [`ByHashUnit`]: probe the by-hash tree, build its `Release`
/// reference set, and sweep the leftovers.
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
    unit: &ByHashUnit,
    ctx: &MirrorCtx<'_>,
) -> Result<UnitStats, CleanupUnitError> {
    let mirror = ctx.mirror;
    let layout = unit.layout;

    // Cheap absence check: skip the origins query + Release reads for a mirror
    // whose per-layout by-hash tree does not exist.
    if !byhash_dir_present(&unit.root).await {
        return Ok(UnitStats::default());
    }

    // Build the union reference set (`None` ⇒ age-based fallback for the whole
    // tree). Structured trees gate reference mode on the complete active-origin
    // distribution set; a DB error there forces age mode (never reconcile
    // against a possibly-incomplete origin set). Flat trees have a single root
    // Release and no per-dist union, so they pass an empty expected list.
    let reference = match unit.dist_gate {
        DistGate::ActiveOriginDists => match active_origin_distributions(ctx.self_origins) {
            Some(expected_dists) => {
                build_byhash_reference_set(&unit.release_dir, layout, &expected_dists).await
            }
            None => None,
        },
        DistGate::None => build_byhash_reference_set(&unit.release_dir, layout, &[]).await,
    };

    let outcome = sweep_byhash_dir(
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
/// (swept past `backstop`). A symlink / FIFO / socket / device is unlinked
/// inline and counts toward `removed`; a stray directory is reported and
/// retained. Removal, metadata invalidation, future-timestamp and I/O-error
/// handling all flow through [`sweep_candidates`].
///
/// `NotFound` is treated as "nothing to do" (TOCTOU: the caller pre-probes with
/// `byhash_dir_present`, but the tree may vanish in between).
static BYHASH_WALK: WalkContext = WalkContext {
    what: "a by-hash directory",
    dir_failure: DirFailure::Abort("abandoning its cleanup this cycle"),
    entry_failure: "retaining it",
    non_regular: "removing it",
};

async fn sweep_byhash_dir(
    byhash_path: &Path,
    reference: Option<&ByHashReferenceSet>,
    grace: Duration,
    backstop: Duration,
    now: SystemTime,
    mirror: &Mirror,
    layout: CacheLayout,
) -> Result<ByHashOutcome, CleanupUnitError> {
    let mut candidates: HashMap<OsString, SpanClass> = HashMap::new();
    let mut anomaly_removed = 0u64;
    let mut referenced_kept = 0u64;

    let mut walker = Walker::new(byhash_path, &BYHASH_WALK, OnMissing::Tolerate, ());

    while let Some(entry) = walker.next().await {
        match entry.kind() {
            EntryKind::NonRegular => {
                if remove_non_regular(&entry.path()).await {
                    anomaly_removed += 1;
                }
                continue;
            }
            EntryKind::Dir => {
                entry.report_unexpected("retaining it and excluding its contents from cleanup");
                continue;
            }
            EntryKind::File => {}
        }

        // Classify against the reference set inline (reference mode). A
        // referenced digest is kept forever regardless of age, so it never
        // enters the candidate map — in a healthy tree that is the bulk of the
        // directory, and skipping it saves an owned key plus a map slot. An
        // unreferenced covered digest gets the grace span; an uncovered
        // algorithm, an unclassifiable name, or age mode (`reference` is `None`)
        // gets the backstop, exactly as the old walk treated them.
        let name = entry.name();
        let classified = reference
            .zip(name.to_str())
            .and_then(|(refset, digest)| refset.classify(digest).map(|c| (refset, c)));
        let class = match classified {
            Some((_refset, (_algo, true))) => {
                referenced_kept += 1;
                continue;
            }
            Some((refset, (algo, false))) if refset.covers(algo) => SpanClass::ByHashCovered,
            Some(_) | None => SpanClass::ByHashUncovered,
        };

        candidates.insert(name.to_owned(), class);
    }

    match walker.finish() {
        WalkOutcome::Complete | WalkOutcome::RootMissing => {}
        WalkOutcome::Aborted { logged, err: _ } => return Err(CleanupUnitError(logged)),
    }

    let survivors = candidates.len() as u64;
    let swept = sweep_candidates(
        byhash_path,
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
    unit: &ReconcileUnit,
    mirror_ctx: &MirrorCtx<'_>,
) -> Result<UnitStats, CleanupUnitError> {
    let layout = unit.facet.cache_layout();
    let policy = unit.policy;
    let &MirrorCtx {
        mirror,
        entry,
        appstate,
        config,
        self_origins,
        now,
    } = mirror_ctx;

    // An unreadable directory was logged by the walker; the unit is abandoned.
    let mut cached_files = scan_candidates(&unit.tree, &entry.path).await?;

    trace!("Cached files ({}): {cached_files:?}", cached_files.len());

    let mut tally = UnitStats {
        scanned: cached_files.len() as u64,
        removed: 0,
        bytes_removed: 0,
        removed_unreferenced: 0,
    };

    let ctx = ReconcileCtx {
        policy,
        self_origins,
        tree_root: &unit.tree.root,
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
        match resolve_group(&ctx, group, &mut cached_files, &mut tally).await {
            GroupResolution::Exhausted => return Ok(tally),
            GroupResolution::Skipped => {}
            GroupResolution::Ran(outcome) => {
                // An owning group that Completed owns the whole reconciliation:
                // stop resolving further groups and grace-sweep the leftovers.
                let owning_complete = group.owning && matches!(outcome, GroupOutcome::Complete);
                // The resolver reports only the outcome; `owning`/`root_seg`
                // come straight off the group the classifier emitted, so they
                // cannot drift from it.
                results.push(GroupResult {
                    owning: group.owning,
                    root_seg: flat_root_segment(&group.source).map(str::to_owned),
                    outcome,
                });
                if owning_complete {
                    owning_root = archive_root_segment(&group.source);
                    break;
                }
            }
        }
    }

    // Nothing to sweep (the tree scanned empty; a reduce that emptied the map
    // already short-circuited as `Exhausted`). Skip the no-op sweep + its
    // summary, matching the previous empty-cache early return.
    if cached_files.is_empty() {
        return Ok(tally);
    }

    // The shared decision core: policy + group results -> spans + reason.
    let (spans, reason) = match decide_sweep(policy, &results) {
        SweepAction::Sweep { spans, reason } => (spans, reason),
        // Conservative bail: no sweep this cycle. The resolver
        // already emitted the per-origin warn with the failing host/path/status.
        SweepAction::Bail => return Ok(tally),
    };

    // The age fallback announces itself before sweeping: every index source
    // failed, so the reference set is incomplete and leftovers age out on the
    // long span instead of the short grace. Only the flat facet
    // (`ReferencedOrAge`) ever gets here.
    if let SweepReason::AgeFallback {
        primary,
        root_failed,
    } = &reason
    {
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
        let suffix = match root_failed {
            Some((seg, root_status)) if root_status != primary => {
                format!(", flat-root `{seg}` {root_status}")
            }
            _ => String::new(),
        };
        warn!(
            "Failed to fetch the flat Packages index for mirror {mirror} ({primary}{suffix}); falling back to time-based retention over {}",
            HumanFmt::Time(spans.deb)
        );
    }

    let swept = sweep_candidates(&unit.tree.root, &cached_files, spans, now, mirror, layout).await;

    match reason {
        SweepReason::AgeFallback {
            primary: _,
            root_failed: _,
        } => info!(
            "Removed {} aged flat deb files for mirror {mirror} ({})",
            swept.files_removed,
            HumanFmt::Size(swept.bytes_removed)
        ),
        // Strict-hybrid finish: the owning archive-root group reconciled this
        // flat-pool mirror against the structured `dists/` index of its archive
        // root, so name the root instead of emitting the generic per-facet
        // summary. Reaching the sweep with an empty map is impossible here: a
        // reduce that empties it returns `Exhausted`, which short-circuits above.
        SweepReason::Grace => match owning_root {
            Some(archive_root) => info!(
                "Strict-reconciled flat-pool mirror {mirror} against archive root `{archive_root}`: removed {} unreferenced deb files ({})",
                swept.files_removed,
                HumanFmt::Size(swept.bytes_removed)
            ),
            None => log_reconcile_removed(unit.facet, mirror, &swept),
        },
    }
    tally.fold(swept);

    Ok(tally)
}

/// Dispatch one [`SourceGroup`] to its resolver: the structured-pool, hybrid
/// archive-root, and flat (root-segment / co-located) sources. Every
/// [`IndexSource`] variant has an arm here — the by-hash `Release` digest set is
/// not one of them, it lives on the [`ByHashUnit`] payload.
async fn resolve_group(
    ctx: &ReconcileCtx<'_>,
    group: &SourceGroup,
    cached_files: &mut HashMap<OsString, SpanClass>,
    tally: &mut UnitStats,
) -> GroupResolution {
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
        | IndexSource::FlatPackages { fetch: _ } => None,
    }
}

/// Extract the flat-repo root segment of a root-segment source. Stamped onto
/// the group's [`GroupResult`] by the tail so [`decide_sweep`] can name it in
/// the age-fallback warn suffix; only [`FlatFetch::RootSegment`] carries one.
fn flat_root_segment(source: &IndexSource) -> Option<&str> {
    match source {
        IndexSource::FlatPackages {
            fetch: FlatFetch::RootSegment { seg, prefix: _ },
        } => Some(seg.as_str()),
        IndexSource::FlatPackages {
            fetch: FlatFetch::Colocated,
        }
        | IndexSource::OriginPackages {
            origin_rows_of: _,
            keymap: _,
            cache_layout: _,
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

/// The `mirrors_v2` row gate shared by the two resolvers whose referencing
/// index belongs to *another* row (the archive root, the flat-repo root):
/// cleanup never mints a row, so the group runs only when that row exists.
/// `Ok(())` proceeds; `Err` is the group's resolution (`NoRow`, or `DbError`
/// after the one error line naming `noun`).
async fn gate_on_row(
    ctx: &ReconcileCtx<'_>,
    seg: &str,
    noun: &'static str,
) -> Result<(), GroupResolution> {
    match ctx
        .appstate
        .database
        .mirror_exists(ctx.mirror.host(), ctx.mirror.port(), seg)
        .await
    {
        Ok(true) => Ok(()),
        Ok(false) => Err(GroupResolution::Ran(GroupOutcome::NotApplicable(
            SkipReason::NoRow {
                seg: seg.to_owned(),
            },
        ))),
        Err(err) => {
            metrics::DB_OPERATION_FAILED.increment();
            error!(
                "Failed to check the mirror row of {noun} `{seg}`; continuing with the mirror's remaining index sources:  {}",
                ErrorReport(&err)
            );
            Err(GroupResolution::Ran(GroupOutcome::NotApplicable(
                SkipReason::DbError,
            )))
        }
    }
}

/// The fetch-buffer-reduce plan for one active origin's `dists/.../Packages*`
/// index, shared by the two origin-driven resolvers.  `fetch_mirror` is the
/// row the index is fetched through (the mirror itself, or its archive
/// root); `owner_mirror` is where the candidate debs live and keys their
/// `cache_metadata` invalidation, so it is the reconciled mirror in both.
fn origin_fetch_plan<'a>(
    fetch_mirror: &Mirror,
    owner_mirror: &Mirror,
    origin: &OriginEntry,
    cache_layout: CacheLayout,
    keymap: KeyMapper<'a>,
) -> FetchPlan<'a> {
    FetchPlan {
        mirror: fetch_mirror.clone(),
        owner_mirror: owner_mirror.clone(),
        base_uri: origin.uri(),
        layout: PackagesLayout::Dists,
        cache_layout,
        debname: DebnameKind::OriginScoped {
            distribution: origin.distribution.clone(),
            component: origin.component.clone(),
            architecture: origin.architecture.clone(),
        },
        keymap,
    }
}

/// The one mapping of a [`reduce_against`] outcome onto a group's
/// resolution, shared by every resolver: `Continue` means the index reduced
/// and the resolver carries on (its next origin, or `Complete`); `Break`
/// carries the group's resolution.  An emptied candidate map short-circuits
/// as `Exhausted`; a fetch failure is handed to `on_fetch_failed` for the
/// resolver's own diagnostic (the structured-pool bail warn, the hybrid
/// debug line, or nothing where the tail's age-fallback warn reports the
/// status) before resolving to `FetchFailed`; a reduce error is logged here,
/// once, as `Failed to reduce {index} for mirror {mirror}; {consequence}:
/// {cause}` - the cause ([`ReduceError`]) is unlogged until this point -
/// and resolves to `ParseError`.
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
    cached_files: &mut HashMap<OsString, SpanClass>,
    tally: &mut UnitStats,
) -> GroupResolution {
    let &ReconcileCtx {
        policy: _,
        self_origins: _,
        tree_root,
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
        return GroupResolution::Skipped;
    }

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
                ErrorReport(&err)
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
        return GroupResolution::Ran(GroupOutcome::NotApplicable(SkipReason::NoActiveOrigins));
    }

    let archive_mirror = Mirror::new(
        mirror.host().clone(),
        mirror.port(),
        root.to_owned(),
        MirrorKind::Structured,
    );

    for origin in &active_origins {
        // The debs live under the original flat sub-path `mirror`, not the
        // archive root, so metadata invalidation must key by `mirror`.
        let plan = origin_fetch_plan(
            &archive_mirror,
            mirror,
            origin,
            cache_layout,
            keymapper_for(keymap),
        );
        let step = map_reduce(
            reduce_against(&plan, tree_root, cached_files, tally, appstate, config).await,
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
    cached_files: &mut HashMap<OsString, SpanClass>,
    tally: &mut UnitStats,
) -> GroupResolution {
    let &ReconcileCtx {
        policy: _,
        self_origins: _,
        tree_root,
        mirror,
        entry: _,
        appstate,
        config,
    } = ctx;

    // Skip the DB gate + fetch when there is nothing to reconcile (see the
    // hybrid resolver's guard for the debug-assert rationale).
    if cached_files.is_empty() {
        return GroupResolution::Skipped;
    }

    if let Err(resolution) = gate_on_row(ctx, seg, "flat-repo root").await {
        return resolution;
    }

    let plan = flat_root_fetch_plan(mirror, seg, prefix);
    // A fetch failure is silent here: the tail's age-fallback warn reports
    // the root status next to the co-located one.
    match map_reduce(
        reduce_against(&plan, tree_root, cached_files, tally, appstate, config).await,
        mirror,
        format_args!("the flat-root Packages index `{seg}`"),
        "falling back to time-based retention",
        |_status| {},
    ) {
        ControlFlow::Continue(()) => GroupResolution::Ran(GroupOutcome::Complete),
        ControlFlow::Break(resolution) => resolution,
    }
}

/// Co-located flat source resolver (`FlatPackages { Colocated }`): the
/// always-last group, reconciling the mirror's own debs against its co-located
/// `<mirror.path>/Packages*` index (`keymap: Relpath`, `owner_mirror = mirror`).
/// Never `owning`. `decide_sweep` reads this (the last) group's outcome to pick
/// grace vs age fallback.
async fn resolve_flat_colocated(
    ctx: &ReconcileCtx<'_>,
    cached_files: &mut HashMap<OsString, SpanClass>,
    tally: &mut UnitStats,
) -> GroupResolution {
    let &ReconcileCtx {
        policy: _,
        self_origins: _,
        tree_root,
        mirror,
        entry: _,
        appstate,
        config,
    } = ctx;

    // Skip the co-located fetch when there is nothing to reconcile (see the
    // hybrid resolver's guard for the debug-assert rationale).
    if cached_files.is_empty() {
        return GroupResolution::Skipped;
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
    // A fetch failure is silent here: the tail's age-fallback warn reports
    // the co-located status.
    match map_reduce(
        reduce_against(&plan, tree_root, cached_files, tally, appstate, config).await,
        mirror,
        format_args!("the co-located flat Packages index"),
        "falling back to time-based retention",
        |_status| {},
    ) {
        ControlFlow::Continue(()) => GroupResolution::Ran(GroupOutcome::Complete),
        ControlFlow::Break(resolution) => resolution,
    }
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
    cached_files: &mut HashMap<OsString, SpanClass>,
    tally: &mut UnitStats,
) -> GroupResolution {
    let &ReconcileCtx {
        policy,
        self_origins,
        tree_root,
        mirror,
        entry,
        appstate,
        config,
    } = ctx;

    // The grace window is used only for the diagnostics below; the tail derives
    // the sweep spans from the same policy.
    let grace = policy.grace();

    let Some(origins) = self_origins else {
        // The origins read failed (logged and counted at the read site): we
        // cannot tell which cached debs are still referenced. Hand the tail a
        // `DbError`, which `decide_sweep` turns into a bail -- treating it as
        // "no origins" would grace-sweep files we never got to check.
        return GroupResolution::Ran(GroupOutcome::NotApplicable(SkipReason::DbError));
    };

    trace!("Origins ({}): {origins:?}", origins.len());

    let now: Duration = Clock::now_since_epoch().into();

    trace!("Now: {now:?}");

    let origins_count = origins.len();
    // Most-recent last_seen across all origin rows (in epoch seconds).
    // Used purely for the diagnostic log below when every row is stale.
    let most_recent_origin: i64 = origins.iter().map(|o| o.last_seen).max().unwrap_or(0);

    let active_origins = origins
        .iter()
        .filter(|origin| origin.is_active(now))
        .collect::<Vec<_>>();

    info!(
        "Found {} active origins and {} cached deb files for mirror {mirror} (`{}`)",
        active_origins.len(),
        cached_files.len(),
        entry.site(),
    );

    // Diagnostic: cached debs exist but cleanup will fetch no Packages
    // index (no active origins).  Surface enough context to disambiguate
    // "no recent .deb traffic" (origins present but stale) from "origins
    // never recorded" (origins_count == 0).  Cheap: one extra info line
    // per cleanup cycle, only when the smelly state actually fires.
    if !cached_files.is_empty() && active_origins.is_empty() {
        if origins_count == 0 {
            info!(
                "Mirror {mirror}: no origin records, so cached debs cannot be reconciled against any Packages index; aging them out via the {} grace window",
                HumanFmt::Time(grace),
            );
        } else {
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
    }

    // No candidates, or no active origin index to reduce against: the group
    // does not run. `decide_sweep` on the resulting empty result set returns
    // `Grace`, matching the previous grace sweep (empty active origins swept
    // the leftovers). Returning early also avoids fetching a `Packages` index
    // when there are no debs to reconcile (which would otherwise stall on an
    // absent upstream).
    if cached_files.is_empty() || active_origins.is_empty() {
        return GroupResolution::Skipped;
    }

    // One fetch-buffer-reduce plan per active origin, built as its turn comes:
    // the loop bails on the first failure, so materialising every plan up front
    // would allocate for origins that are never probed. `keymap: Basename`
    // because the structured pool flattens `Filename:` relpaths to basename;
    // `layout: Dists` is where the referencing `Packages` index lives.
    for origin in active_origins {
        let plan = origin_fetch_plan(
            mirror,
            mirror,
            origin,
            CacheLayout::StructuredPool,
            KeyMapper::Basename,
        );
        // A missing Packages file leaves us unable to complete the reference
        // set; deleting now risks wiping files referenced only by this origin
        // (typical when a distribution goes EOL upstream). Warn here
        // (host/path/status in hand) and hand the tail a `FetchFailed` so
        // `decide_sweep` returns `Bail` - no sweep this cycle. A reduce error
        // (malformed/decompression-bomb index, local read failure) leaves the
        // reference set incomplete just like a fetch miss, so it bails too.
        let step = map_reduce(
            reduce_against(&plan, tree_root, cached_files, tally, appstate, config).await,
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

    // Every active origin's index reduced; leftovers are genuinely
    // unreferenced. `decide_sweep(ReferencedOrBail, [Complete])` returns
    // `Grace`, so the tail reaps them on the short grace span.
    GroupResolution::Ran(GroupOutcome::Complete)
}

/// Per-facet reconcile-sweep completion summary for the `Grace` action —
/// only the structured-pool and flat facets reach it (the by-hash units emit
/// their own summary in `run_byhash_unit`). The flat `AgeFallback` path emits
/// its own "aged flat deb files" line rather than routing through here.
fn log_reconcile_removed(facet: ReconcileFacet, mirror: &Mirror, swept: &SweepResult) {
    match facet {
        ReconcileFacet::StructuredPool => info!(
            "Removed {} unreferenced deb files for mirror {mirror} ({})",
            swept.files_removed,
            HumanFmt::Size(swept.bytes_removed)
        ),
        ReconcileFacet::FlatTree => info!(
            "Removed {} unreferenced flat deb files for mirror {mirror} ({})",
            swept.files_removed,
            HumanFmt::Size(swept.bytes_removed)
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ClientHost;
    use crate::test_support::structured_mirror;

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

    use crate::deb_mirror::MirrorKind;
    use crate::index_parser::hex_encode;

    const DAY: u64 = 24 * 60 * 60;

    fn byhash_test_mirror() -> Mirror {
        structured_mirror("deb.example.org", "debian")
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
