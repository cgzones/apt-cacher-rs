//! Pure cleanup data model: what to clean, against which index sources, and
//! how leftovers are retained. No I/O — classification and the sweep decision
//! are unit-testable truth tables.

use std::path::PathBuf;
use std::time::Duration;

use http::StatusCode;
use tracing::trace;

use crate::RETENTION_TIME;
use crate::cache_layout::CacheLayout;
use crate::cache_paths::{CachePaths, SUBDIR_FLAT_BYHASH, SUBDIR_TMP};
use crate::cleanup::packages::FetchFailure;
use crate::cleanup::sweep::SpanTable;
use crate::config::Config;
use crate::database::MirrorEntry;
use crate::deb_mirror::{MirrorKind, flat_pool_archive_root};

/// Grace period for unreferenced cached deb files. Apt updates that bypass
/// the proxy register their origin lazily; this delay prevents a freshly
/// cached file from being wiped before its origin row is observed.
const UNREFERENCED_KEEP_SPAN: Duration = Duration::from_hours(3 * 24);

/// Retention span for volatile index metadata (`Release`/`InRelease`/`Packages*`
/// /...) in a structured `dists/` directory. Unlike per-`.deb` files these are
/// refreshed in place (a fresh inode, hence a fresh birthtime) while a
/// distribution is in use, so aging past this span marks the distribution as
/// retired. Nothing else reclaims these files, and while a retired dist's
/// `Release` lingers, reference-mode by-hash cleanup keeps every digest it lists
/// pinned; removing the metadata bounds the growth and unblocks that reclaim.
/// See `sweep::sweep_aged_metadata`.
const METADATA_KEEP_SPAN: Duration = Duration::from_hours(90 * 24);

/// Age threshold for a `.partial` scratch file, carried as the [`PartialsUnit`]
/// span and applied by `partials::cleanup_tmp_dir` (which keeps its own, longer
/// backstop for foreign entries).
const PARTIALS_KEEP_SPAN: Duration = Duration::from_hours(3 * 24);

/// Which candidate-reconcile tree a [`ReconcileUnit`] targets. Both shapes run
/// the same engine and differ only in where they anchor and how their
/// completion summary reads — the other three unit shapes need no such
/// discriminator, their [`CleanupUnit`] variant *is* the shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ReconcileFacet {
    /// Structured pool tree: `{host}/{path}/`, depth-1, basename-keyed.
    StructuredPool,
    /// Flat repository tree: `{host}/flat/{path}/`, recursive, relpath-keyed.
    FlatTree,
}

impl ReconcileFacet {
    /// The layout this facet's tree is anchored under: it *places* the tree
    /// (`CachePaths::entry_dir`) and is the key its sweep invalidates
    /// `cache_metadata` on. Derived here rather than carried alongside the facet so the root the
    /// classifier builds and the key the engine invalidates on cannot disagree.
    pub(super) const fn cache_layout(self) -> CacheLayout {
        match self {
            Self::StructuredPool => CacheLayout::StructuredPool,
            Self::FlatTree => CacheLayout::Flat,
        }
    }
}

/// One independently-cleaned tree, in the shape its executor consumes.
///
/// The variant *is* the retention rule: each payload carries exactly the inputs
/// its `engine.rs` arm needs and nothing else, so a tree paired with a rule that
/// cannot execute it — a by-hash tree with an age-only span, a `tmp/` reap with
/// a `Release` digest set — is unrepresentable rather than guarded against at
/// runtime.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum CleanupUnit {
    /// Scan a tree into a candidate map, reduce it against ordered index
    /// sources, sweep what survives. The only shape carrying [`SourceGroup`]s.
    Reconcile(ReconcileUnit),
    /// Sweep a by-hash tree against an on-disk `Release` digest set. Fetches
    /// nothing and reduces nothing.
    ByHash(ByHashUnit),
    /// Age out stale index metadata in place.
    Metadata(MetadataUnit),
    /// Reap stale partial-download scratch files from one `tmp/` directory.
    Partials(PartialsUnit),
}

/// A [`CleanupUnit::Reconcile`] unit: the tree to scan, the ordered index
/// sources that reduce its candidate map, and how leftovers are retained.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct ReconcileUnit {
    pub facet: ReconcileFacet,
    pub tree: TreeSpec,
    pub groups: Vec<SourceGroup>,
    pub policy: ReconcilePolicy,
}

/// A [`CleanupUnit::ByHash`] unit. `release_dir`/`dist_gate` name the on-disk
/// `Release` set that *defines* "referenced" — the by-hash counterpart of a
/// reconcile unit's [`SourceGroup`]s, except nothing is fetched. A complete
/// reference set keeps referenced digests and sweeps unreferenced-but-covered
/// ones past `grace`; anything uncovered (or the whole tree, when the reference
/// set is incomplete) sweeps past `backstop`.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct ByHashUnit {
    /// Places the tree (`CachePaths::entry_dir`) and keys its `cache_metadata`
    /// invalidation.
    pub layout: CacheLayout,
    pub root: PathBuf,
    pub release_dir: PathBuf,
    pub dist_gate: DistGate,
    pub grace: Duration,
    pub backstop: Duration,
}

/// A [`CleanupUnit::Metadata`] unit: a pure age sweep of `root`, with no
/// reference source at all.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct MetadataUnit {
    /// Places the tree (`CachePaths::entry_dir`) and keys its `cache_metadata`
    /// invalidation.
    pub layout: CacheLayout,
    pub root: PathBuf,
    pub span: Duration,
}

/// A [`CleanupUnit::Partials`] unit: a pure age reap of one `tmp/` directory.
/// Carries no [`CacheLayout`] — the layout only ever placed the root, and `tmp/`
/// scratch files never enter the metadata store.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct PartialsUnit {
    pub root: PathBuf,
    pub span: Duration,
}

/// Where a [`ReconcileUnit`] scans on disk and how the walk is bounded. Consumed
/// verbatim by [`scan::scan_candidates`](crate::cleanup::scan::scan_candidates);
/// the three non-reconcile shapes scan nothing and carry a plain root instead.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct TreeSpec {
    /// On-disk root of the tree to scan.
    pub root: PathBuf,
    /// How far below `root` the scan reaches.
    pub walk: Walk,
}

/// Recursion policy of a [`TreeSpec`].
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Walk {
    /// Depth-1 walk with basename keys - the structured pool's shape, where
    /// a deb-named directory is a stray entry.
    Shallow,
    /// Full walk with relpath keys - the flat tree's shape.
    Recursive {
        /// Sub-directory names skipped wherever they occur (`by-hash/` and
        /// `tmp/` for flat mirrors).
        skip_subdirs: &'static [&'static str],
        /// Mirror paths of registered siblings that live *inside* this
        /// mirror's path (`deb_mirror::derive_nested_paths`). When the walk
        /// reaches a directory whose mirror-path equivalent is at or inside
        /// one of these, the subtree is skipped (the nested mirror owns it
        /// and runs its own cleanup).
        boundaries: Vec<String>,
    },
}

impl TreeSpec {
    /// A depth-1, unbounded walk of `root` - the structured pool's shape;
    /// [`ReconcileFacet::FlatTree`] is the only recursive tree.
    fn shallow(root: PathBuf) -> Self {
        Self {
            root,
            walk: Walk::Shallow,
        }
    }
}

/// One source *description* applied to the unit's candidate map. Per-origin
/// fan-out happens at resolution time in the engine and is conjunctive there:
/// an `OriginPackages` group counts as complete only when every one of its
/// origins' `Packages` fetches resolved.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct SourceGroup {
    pub source: IndexSource,
    pub owning: bool,
}

/// A reference-set source that reduces a *reconcile* unit's candidate map. The
/// by-hash facets carry their `Release` digest source on their retention policy
/// instead, so every variant here is one `resolve_group` can actually dispatch.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum IndexSource {
    /// Per-active-origin structured `Packages` fetch.
    OriginPackages {
        origin_rows_of: OriginOwner,
        keymap: KeymapSpec,
        cache_layout: CacheLayout,
    },
    /// A flat-repository `Packages` fetch (co-located or root-segment).
    FlatPackages { fetch: FlatFetch },
}

/// Whose `mirrors_v2` row the active origins are read from for an
/// [`IndexSource::OriginPackages`] group.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum OriginOwner {
    /// The row being cleaned itself.
    SelfRow,
    /// The Gitea/Forgejo archive-root row (issue #162 hybrid).
    ArchiveRoot { root: String },
}

/// How a `Packages` stanza's `Filename` field maps to a candidate map key.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum KeymapSpec {
    /// Key on the basename only (structured pool).
    Basename,
    /// Key on the relative path with a fixed prefix stripped.
    RelpathUnderPrefix { prefix: String },
}

/// Where a flat `Packages` index is fetched from.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum FlatFetch {
    /// Fetched from the same mirror path being cleaned.
    Colocated,
    /// Fetched from a flat-root segment above the mirror path (issue #162).
    RootSegment { seg: String, prefix: String },
}

/// Whether a [`ByHashUnit`] requires every expected active-origin distribution
/// to be present before its `Release` digest set counts as complete.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum DistGate {
    /// Complete only when every active-origin distribution's `Release` is
    /// present and readable.
    ActiveOriginDists,
    /// No completeness gate (flat trees have no distributions).
    None,
}

/// How a [`ReconcileUnit`] retains leftovers once its ordered [`SourceGroup`]s
/// have run. The only policy [`decide_sweep`] takes: the by-hash and age-only
/// shapes carry their retention on their own payloads and never reach it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ReconcilePolicy {
    /// Structured pool: any group fetch/parse failure bails the whole unit
    /// (no sweep this cycle); otherwise sweep past `grace`
    /// (`UNREFERENCED_KEEP_SPAN`).
    ReferencedOrBail { grace: Duration },
    /// Flat: sweep past `grace` when the reference set is usable per the
    /// `decide_sweep` truth table (note the quirk: a co-located parse error
    /// forces the fallback even when the root group completed); otherwise
    /// fall back to age-based `fallback` (`RETENTION_TIME`).
    ReferencedOrAge { grace: Duration, fallback: Duration },
}

impl ReconcilePolicy {
    /// The short span leftovers are reaped past once the reference set proved
    /// usable. Also the window the structured resolver names in its
    /// no-active-origins diagnostics.
    pub(super) const fn grace(self) -> Duration {
        match self {
            Self::ReferencedOrBail { grace } | Self::ReferencedOrAge { grace, fallback: _ } => {
                grace
            }
        }
    }
}

/// Outcome of resolving one [`SourceGroup`] against the candidate map.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum GroupOutcome {
    /// The source resolved and reduced the candidate map (or had nothing to
    /// reduce).
    Complete,
    /// The group's precondition did not hold; it never ran.
    NotApplicable(SkipReason),
    /// The upstream (or on-disk) fetch failed.
    FetchFailed(FetchFailure),
    /// The fetch succeeded but the content failed to parse (truncation,
    /// malformed stanza, oversize).
    ParseError,
}

/// Why a [`GroupOutcome::NotApplicable`] group never ran.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum SkipReason {
    /// The gating `mirrors_v2` row (e.g. the archive-root row for a hybrid
    /// group) does not exist.
    NoRow { seg: String },
    /// A DB lookup needed to resolve the group failed.
    DbError,
    /// The gating row exists but has no active origins.
    NoActiveOrigins,
}

/// Result of running one [`SourceGroup`] in a unit, carrying the context
/// `decide_sweep` needs to build a diagnostic warn suffix.
#[derive(Debug)]
pub(super) struct GroupResult {
    pub owning: bool,
    /// Set for [`FlatFetch::RootSegment`] groups — feeds the warn suffix.
    pub root_seg: Option<String>,
    pub outcome: GroupOutcome,
}

/// Final sweep decision for a unit, derived from its policy and the group
/// results. Carries the spans, so the engine never re-derives them from the
/// policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum SweepAction {
    /// Sweep leftover candidates on `spans`; `reason` selects the engine's
    /// diagnostics and completion summary.
    Sweep {
        spans: SpanTable,
        reason: SweepReason,
    },
    /// Bail: no sweep this cycle.
    Bail,
}

/// Why a [`SweepAction::Sweep`] is happening, and on what evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum SweepReason {
    /// At least one source reconciled (or none needed to): leftovers are
    /// genuinely unreferenced and reaped past the policy's short grace span.
    Grace,
    /// Every index source failed, so the reference set is incomplete and
    /// leftovers age out on the long fallback span instead. Carries the primary
    /// fetch failure and, when the root fallback was attempted and fetch-failed,
    /// the root-segment failure (the warn site only renders it when its status
    /// differs from the primary).
    AgeFallback {
        primary: FetchFailure,
        root_failed: Option<(String, FetchFailure)>,
    },
}

/// Final sweep decision for a unit from its policy and the ordered results of
/// the groups that ran. The whole flat-cascade fallback table lives here —
/// replacing the ad-hoc state threading of the previous implementation.
pub(super) fn decide_sweep(policy: ReconcilePolicy, groups: &[GroupResult]) -> SweepAction {
    let grace_sweep = || SweepAction::Sweep {
        spans: SpanTable::uniform(policy.grace()),
        reason: SweepReason::Grace,
    };

    match policy {
        ReconcilePolicy::ReferencedOrBail { grace: _ } => {
            for g in groups {
                match &g.outcome {
                    // A gate that legitimately did not apply (no row, no active
                    // origins) means there is no reference set to be had, which
                    // the grace sweep already handles.
                    GroupOutcome::Complete
                    | GroupOutcome::NotApplicable(
                        SkipReason::NoRow { seg: _ } | SkipReason::NoActiveOrigins,
                    ) => {}
                    // A DB error is different: the reference set is *unknown*,
                    // not empty, so sweeping could delete a still-referenced
                    // deb. Bail like a failed fetch.
                    GroupOutcome::NotApplicable(SkipReason::DbError)
                    | GroupOutcome::FetchFailed(_)
                    | GroupOutcome::ParseError => {
                        return SweepAction::Bail;
                    }
                }
            }
            grace_sweep()
        }
        ReconcilePolicy::ReferencedOrAge { grace: _, fallback } => {
            let age_sweep = |primary, root_failed| SweepAction::Sweep {
                spans: SpanTable::uniform(fallback),
                reason: SweepReason::AgeFallback {
                    primary,
                    root_failed,
                },
            };

            // An owning group that completed ended reconciliation (the engine
            // stops early), so its presence as the last result means Grace.
            if let Some(last) = groups.last()
                && last.owning
                && matches!(last.outcome, GroupOutcome::Complete)
            {
                return grace_sweep();
            }
            // Otherwise the last group is the always-present co-located probe.
            let Some(colocated) = groups.last() else {
                return grace_sweep();
            };
            let root = groups
                .iter()
                .rev()
                .skip(1)
                .find(|g| g.root_seg.is_some() && !g.owning);
            match &colocated.outcome {
                GroupOutcome::Complete | GroupOutcome::NotApplicable(_) => grace_sweep(),
                // A parse error falls back to age retention even when the
                // root index reduced fine — quirk preserved from the previous
                // implementation. See truth-table test.
                GroupOutcome::ParseError => age_sweep(
                    FetchFailure {
                        status: StatusCode::BAD_GATEWAY,
                        upstream: None,
                    },
                    None,
                ),
                GroupOutcome::FetchFailed(primary) => match root.map(|g| (&g.outcome, g)) {
                    Some((GroupOutcome::Complete, _)) => grace_sweep(),
                    Some((GroupOutcome::FetchFailed(rf), g)) => age_sweep(
                        primary.clone(),
                        g.root_seg.clone().map(|seg| (seg, rf.clone())),
                    ),
                    _ => age_sweep(primary.clone(), None),
                },
            }
        }
    }
}

/// Split a flat mirror path into its flat-repo root segment and the in-mirror
/// sub-path prefix (with a trailing `/`) that must be stripped from a root
/// `Packages` index's `Filename:` values before matching cached debs.
///
/// Returns `None` when the path has no ancestor segment distinct from itself
/// (single-segment, or trailing-slash-only like `"apt/"`), so no flat-root
/// fallback applies.
pub(super) fn flat_root_split(mirror_path: &str) -> Option<(&str, String)> {
    let trimmed = mirror_path.trim_end_matches('/');
    let (head, _) = trimmed.split_once('/')?;
    if head.is_empty() {
        return None;
    }
    let mut prefix = trimmed
        .strip_prefix(head)
        .unwrap_or("")
        .trim_matches('/')
        .to_owned();
    if prefix.is_empty() {
        return None; // path was exactly the head segment
    }
    prefix.push('/');
    Some((head, prefix))
}

/// Classify one `mirrors_v2` row into the ordered [`CleanupUnit`]s the engine
/// will probe and sweep this cycle.
///
/// Pure: no I/O, no DB — an absent on-disk tree just means the engine's unit
/// finds nothing to remove. Units are emitted in the exact order the engine
/// executes them: `[Partials(structured tmp), Partials(flat tmp),
/// Reconcile(StructuredPool)?, Reconcile(FlatTree), Metadata(Dists)?,
/// Metadata(Flat), ByHash(DistsByHash)?, ByHash(FlatByHash)]`. The three `?`
/// units are omitted for a `MirrorKind::Flat` row: `kind` latches one-way to
/// `Structured` (see `upsert_mirror_get_id`), so a `Flat` row is guaranteed to
/// have no structured pool tree, dists tree, or dists by-hash tree on disk.
///
/// `nested` is the caller's pre-computed list of sibling mirror paths nested
/// under `entry.path` (`scan::derive_nested_paths`); it becomes the
/// [`ReconcileFacet::FlatTree`] unit's walk boundaries.
///
/// Every unit root is a [`CachePaths::entry_dir`] / [`CachePaths::tmp_dir`]
/// of the mirror's alias-resolved site - the same derivation the serve path
/// writes through (`ConnectionDetails::cache_file_path`), so a layout whose
/// on-disk position moved cannot leave cleanup scanning the old one (finding
/// nothing, reaping nothing, and saying nothing).  Both are computed from
/// `config` (`entry.site_with_aliases(&config.aliases)`) rather than
/// `global_config()`, which panics outside a running daemon: this function
/// must stay callable from a plain unit test.
pub(super) fn classify_mirror(
    entry: &MirrorEntry,
    nested: Vec<String>,
    config: &Config,
) -> Vec<CleanupUnit> {
    let is_flat = entry.kind() == MirrorKind::Flat;

    let paths = CachePaths::new(&config.cache_directory);
    let site = entry.site_with_aliases(&config.aliases);

    let byhash_backstop = Duration::from_secs(24 * 60 * 60 * config.byhash_retention_days.get());

    let mut units = Vec::with_capacity(8);

    // Structured `tmp/` first, then flat `tmp/`. `tmp/` hangs off each anchor
    // rather than off a layout subdirectory, so it is the one root not fully
    // derived from the layout.
    for layout in [CacheLayout::StructuredPool, CacheLayout::Flat] {
        units.push(CleanupUnit::Partials(PartialsUnit {
            root: paths.tmp_dir(layout, site),
            span: PARTIALS_KEEP_SPAN,
        }));
    }

    if is_flat {
        trace!("Skipping structured-pool cleanup for flat mirror {site}");
    } else {
        let facet = ReconcileFacet::StructuredPool;
        units.push(CleanupUnit::Reconcile(ReconcileUnit {
            facet,
            tree: TreeSpec::shallow(paths.entry_dir(facet.cache_layout(), site)),
            groups: vec![SourceGroup {
                source: IndexSource::OriginPackages {
                    origin_rows_of: OriginOwner::SelfRow,
                    keymap: KeymapSpec::Basename,
                    cache_layout: CacheLayout::StructuredPool,
                },
                owning: false,
            }],
            policy: ReconcilePolicy::ReferencedOrBail {
                grace: UNREFERENCED_KEEP_SPAN,
            },
        }));
    }

    let mut flat_groups = Vec::with_capacity(3);
    if let Some((root, prefix)) = flat_pool_archive_root(&entry.path) {
        flat_groups.push(SourceGroup {
            source: IndexSource::OriginPackages {
                origin_rows_of: OriginOwner::ArchiveRoot {
                    root: root.to_owned(),
                },
                keymap: KeymapSpec::RelpathUnderPrefix { prefix },
                cache_layout: CacheLayout::Flat,
            },
            owning: true,
        });
    }
    if let Some((seg, prefix)) = flat_root_split(&entry.path) {
        flat_groups.push(SourceGroup {
            source: IndexSource::FlatPackages {
                fetch: FlatFetch::RootSegment {
                    seg: seg.to_owned(),
                    prefix,
                },
            },
            owning: false,
        });
    }
    flat_groups.push(SourceGroup {
        source: IndexSource::FlatPackages {
            fetch: FlatFetch::Colocated,
        },
        owning: false,
    });

    let facet = ReconcileFacet::FlatTree;
    units.push(CleanupUnit::Reconcile(ReconcileUnit {
        facet,
        tree: TreeSpec {
            root: paths.entry_dir(facet.cache_layout(), site),
            walk: Walk::Recursive {
                skip_subdirs: &[SUBDIR_FLAT_BYHASH, SUBDIR_TMP],
                boundaries: nested,
            },
        },
        groups: flat_groups,
        policy: ReconcilePolicy::ReferencedOrAge {
            grace: UNREFERENCED_KEEP_SPAN,
            fallback: RETENTION_TIME,
        },
    }));

    if !is_flat {
        let layout = CacheLayout::Dists;
        units.push(CleanupUnit::Metadata(MetadataUnit {
            layout,
            root: paths.entry_dir(layout, site),
            span: METADATA_KEEP_SPAN,
        }));
    }

    let layout = CacheLayout::Flat;
    units.push(CleanupUnit::Metadata(MetadataUnit {
        layout,
        root: paths.entry_dir(layout, site),
        span: METADATA_KEEP_SPAN,
    }));

    if !is_flat {
        let layout = CacheLayout::DistsByHash;
        units.push(CleanupUnit::ByHash(ByHashUnit {
            layout,
            root: paths.entry_dir(layout, site),
            // The dists metadata tree -- the same root the structured
            // `Metadata` unit sweeps.
            release_dir: paths.entry_dir(CacheLayout::Dists, site),
            dist_gate: DistGate::ActiveOriginDists,
            grace: UNREFERENCED_KEEP_SPAN,
            backstop: byhash_backstop,
        }));
    }

    let layout = CacheLayout::FlatByHash;
    units.push(CleanupUnit::ByHash(ByHashUnit {
        layout,
        root: paths.entry_dir(layout, site),
        // The flat root -- the same root the flat `Metadata` unit sweeps.
        release_dir: paths.entry_dir(CacheLayout::Flat, site),
        dist_gate: DistGate::None,
        grace: UNREFERENCED_KEEP_SPAN,
        backstop: byhash_backstop,
    }));

    units
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ff(code: u16) -> FetchFailure {
        FetchFailure {
            status: StatusCode::from_u16(code).expect("valid"),
            upstream: None,
        }
    }

    fn gr(outcome: GroupOutcome) -> GroupResult {
        GroupResult {
            owning: false,
            root_seg: None,
            outcome,
        }
    }

    fn root(seg: &str, outcome: GroupOutcome) -> GroupResult {
        GroupResult {
            owning: false,
            root_seg: Some(seg.to_owned()),
            outcome,
        }
    }

    /// The `Grace` decision both test policies produce (their grace is 1s).
    fn grace() -> SweepAction {
        SweepAction::Sweep {
            spans: SpanTable::uniform(Duration::from_secs(1)),
            reason: SweepReason::Grace,
        }
    }

    /// The `AgeFallback` decision `AGE` produces (its fallback is 2s).
    fn age_back(primary: FetchFailure, root_failed: Option<(String, FetchFailure)>) -> SweepAction {
        SweepAction::Sweep {
            spans: SpanTable::uniform(Duration::from_secs(2)),
            reason: SweepReason::AgeFallback {
                primary,
                root_failed,
            },
        }
    }

    fn owning(outcome: GroupOutcome) -> GroupResult {
        GroupResult {
            owning: true,
            root_seg: None,
            outcome,
        }
    }

    const BAIL: ReconcilePolicy = ReconcilePolicy::ReferencedOrBail {
        grace: Duration::from_secs(1),
    };
    const AGE: ReconcilePolicy = ReconcilePolicy::ReferencedOrAge {
        grace: Duration::from_secs(1),
        fallback: Duration::from_secs(2),
    };

    // ReferencedOrBail (structured pool)

    #[test]
    fn bail_no_groups_is_grace() {
        assert_eq!(decide_sweep(BAIL, &[]), grace());
    }

    #[test]
    fn bail_complete_is_grace() {
        assert_eq!(decide_sweep(BAIL, &[gr(GroupOutcome::Complete)]), grace());
    }

    #[test]
    fn bail_fetch_failed_bails() {
        assert_eq!(
            decide_sweep(BAIL, &[gr(GroupOutcome::FetchFailed(ff(404)))]),
            SweepAction::Bail
        );
    }

    #[test]
    fn bail_db_error_bails() {
        // The reference set is unknown rather than empty, so a grace sweep
        // could delete a deb the unread origins still reference.
        assert_eq!(
            decide_sweep(
                BAIL,
                &[gr(GroupOutcome::NotApplicable(SkipReason::DbError))]
            ),
            SweepAction::Bail
        );
    }

    #[test]
    fn bail_no_active_origins_is_grace() {
        assert_eq!(
            decide_sweep(
                BAIL,
                &[gr(GroupOutcome::NotApplicable(SkipReason::NoActiveOrigins))]
            ),
            grace()
        );
    }

    #[test]
    fn bail_parse_error_bails() {
        assert_eq!(
            decide_sweep(BAIL, &[gr(GroupOutcome::ParseError)]),
            SweepAction::Bail
        );
    }

    // ReferencedOrAge (flat; group order = [hybrid?, root?, colocated], colocated ALWAYS last)

    #[test]
    fn age_owning_complete_is_grace() {
        assert_eq!(
            decide_sweep(AGE, &[owning(GroupOutcome::Complete)]),
            grace()
        );
    }

    #[test]
    fn age_colocated_only_complete_is_grace() {
        assert_eq!(decide_sweep(AGE, &[gr(GroupOutcome::Complete)]), grace());
    }

    #[test]
    fn age_colocated_only_fetch_failed_falls_back() {
        assert_eq!(
            decide_sweep(AGE, &[gr(GroupOutcome::FetchFailed(ff(404)))]),
            age_back(ff(404), None)
        );
    }

    #[test]
    fn age_colocated_only_parse_error_falls_back_with_bad_gateway() {
        assert_eq!(
            decide_sweep(AGE, &[gr(GroupOutcome::ParseError)]),
            age_back(ff(502), None)
        );
    }

    #[test]
    fn age_root_complete_is_grace() {
        assert_eq!(
            decide_sweep(
                AGE,
                &[
                    root("apt", GroupOutcome::Complete),
                    gr(GroupOutcome::FetchFailed(ff(404)))
                ]
            ),
            grace()
        );
    }

    #[test]
    fn age_root_failed_and_colocated_failed_falls_back_with_root_context() {
        assert_eq!(
            decide_sweep(
                AGE,
                &[
                    root("apt", GroupOutcome::FetchFailed(ff(403))),
                    gr(GroupOutcome::FetchFailed(ff(404)))
                ]
            ),
            age_back(ff(404), Some(("apt".to_owned(), ff(403))))
        );
    }

    #[test]
    fn age_root_not_applicable_falls_back_without_root_context() {
        assert_eq!(
            decide_sweep(
                AGE,
                &[
                    root(
                        "apt",
                        GroupOutcome::NotApplicable(SkipReason::NoRow {
                            seg: "apt".to_owned()
                        })
                    ),
                    gr(GroupOutcome::FetchFailed(ff(404)))
                ]
            ),
            age_back(ff(404), None)
        );
    }

    #[test]
    fn age_root_parse_error_falls_back_without_root_context() {
        assert_eq!(
            decide_sweep(
                AGE,
                &[
                    root("apt", GroupOutcome::ParseError),
                    gr(GroupOutcome::FetchFailed(ff(404)))
                ]
            ),
            age_back(ff(404), None)
        );
    }

    /// Quirk row: a co-located parse error falls back to age retention even
    /// when the root index reduced fine — behavior preserved from the
    /// previous implementation's colocated-Err arm.
    #[test]
    fn age_colocated_parse_error_ignores_completed_root() {
        assert_eq!(
            decide_sweep(
                AGE,
                &[
                    root("apt", GroupOutcome::Complete),
                    gr(GroupOutcome::ParseError)
                ]
            ),
            age_back(ff(502), None)
        );
    }

    #[test]
    fn age_failed_strict_defers_without_prejudice() {
        assert_eq!(
            decide_sweep(
                AGE,
                &[
                    owning(GroupOutcome::FetchFailed(ff(404))),
                    root("apt", GroupOutcome::Complete),
                    gr(GroupOutcome::FetchFailed(ff(404)))
                ]
            ),
            grace()
        );
    }

    // classify_mirror

    use crate::cache_paths::MirrorSite;
    use crate::config::{Alias, ClientHost};

    fn test_entry(host: &str, path: &str, kind: MirrorKind) -> MirrorEntry {
        MirrorEntry::new_for_test(
            ClientHost::new(host.to_owned()).expect("valid host"),
            None,
            path.to_owned(),
            kind,
        )
    }

    fn test_config(cache_dir: &str) -> Config {
        let mut config: Config = toml::from_str("").expect("built-in defaults must parse");
        config.cache_directory = PathBuf::from(cache_dir);
        config
    }

    /// The single [`ReconcileFacet::FlatTree`] unit every row emits.
    fn flat_tree_unit(units: &[CleanupUnit]) -> &ReconcileUnit {
        units
            .iter()
            .find_map(|u| match u {
                CleanupUnit::Reconcile(r) => (r.facet == ReconcileFacet::FlatTree).then_some(r),
                CleanupUnit::ByHash(_) | CleanupUnit::Metadata(_) | CleanupUnit::Partials(_) => {
                    None
                }
            })
            .expect("FlatTree unit present")
    }

    /// The classifier's whole contract for a structured row, asserted as one
    /// value: shape, order, layout, root, sources and retention together. Every
    /// payload is a struct literal, so a new field on any unit shape is a
    /// compile error here rather than an untested default.
    #[test]
    fn structured_row_emits_all_eight_units_in_order() {
        let entry = test_entry("deb.debian.org", "debian", MirrorKind::Structured);
        let config = test_config("/cache");
        let backstop = Duration::from_secs(24 * 60 * 60 * config.byhash_retention_days.get());

        let units = classify_mirror(&entry, Vec::new(), &config);

        // The roots are spelled out rather than derived so this test pins the
        // on-disk positions themselves; `classify_mirror` derives them from
        // `CachePaths::entry_dir`, the same helper the serve path uses, so a
        // layout that moves on disk moves cleanup's scan with it.
        assert_eq!(
            units,
            vec![
                CleanupUnit::Partials(PartialsUnit {
                    root: PathBuf::from("/cache/deb.debian.org/debian/tmp"),
                    span: PARTIALS_KEEP_SPAN,
                }),
                CleanupUnit::Partials(PartialsUnit {
                    root: PathBuf::from("/cache/deb.debian.org/flat/debian/tmp"),
                    span: PARTIALS_KEEP_SPAN,
                }),
                CleanupUnit::Reconcile(ReconcileUnit {
                    facet: ReconcileFacet::StructuredPool,
                    tree: TreeSpec::shallow(PathBuf::from("/cache/deb.debian.org/debian")),
                    groups: vec![SourceGroup {
                        source: IndexSource::OriginPackages {
                            origin_rows_of: OriginOwner::SelfRow,
                            keymap: KeymapSpec::Basename,
                            cache_layout: CacheLayout::StructuredPool,
                        },
                        owning: false,
                    }],
                    policy: ReconcilePolicy::ReferencedOrBail {
                        grace: UNREFERENCED_KEEP_SPAN,
                    },
                }),
                CleanupUnit::Reconcile(ReconcileUnit {
                    facet: ReconcileFacet::FlatTree,
                    tree: TreeSpec {
                        root: PathBuf::from("/cache/deb.debian.org/flat/debian"),
                        walk: Walk::Recursive {
                            skip_subdirs: &[SUBDIR_FLAT_BYHASH, SUBDIR_TMP],
                            boundaries: Vec::new(),
                        },
                    },
                    groups: vec![SourceGroup {
                        source: IndexSource::FlatPackages {
                            fetch: FlatFetch::Colocated,
                        },
                        owning: false,
                    }],
                    policy: ReconcilePolicy::ReferencedOrAge {
                        grace: UNREFERENCED_KEEP_SPAN,
                        fallback: RETENTION_TIME,
                    },
                }),
                CleanupUnit::Metadata(MetadataUnit {
                    layout: CacheLayout::Dists,
                    root: PathBuf::from("/cache/deb.debian.org/debian/dists"),
                    span: METADATA_KEEP_SPAN,
                }),
                CleanupUnit::Metadata(MetadataUnit {
                    layout: CacheLayout::Flat,
                    root: PathBuf::from("/cache/deb.debian.org/flat/debian"),
                    span: METADATA_KEEP_SPAN,
                }),
                CleanupUnit::ByHash(ByHashUnit {
                    layout: CacheLayout::DistsByHash,
                    root: PathBuf::from("/cache/deb.debian.org/debian/dists/by-hash"),
                    // Exactly the root the structured `Metadata` unit above
                    // sweeps: retiring a `Release` this cycle unpins its digests
                    // in the same cycle.
                    release_dir: PathBuf::from("/cache/deb.debian.org/debian/dists"),
                    dist_gate: DistGate::ActiveOriginDists,
                    grace: UNREFERENCED_KEEP_SPAN,
                    backstop,
                }),
                CleanupUnit::ByHash(ByHashUnit {
                    layout: CacheLayout::FlatByHash,
                    root: PathBuf::from("/cache/deb.debian.org/flat/debian/by-hash"),
                    release_dir: PathBuf::from("/cache/deb.debian.org/flat/debian"),
                    dist_gate: DistGate::None,
                    grace: UNREFERENCED_KEEP_SPAN,
                    backstop,
                }),
            ]
        );
    }

    #[test]
    fn unit_roots_are_the_serve_path_entry_dirs_of_the_aliased_site() {
        // Every root cleanup scans is `CachePaths::entry_dir`/`tmp_dir` of
        // the same `MirrorSite` the serve path writes through - including
        // the alias resolution: the row names the alias host, the tree lives
        // under the alias' main host.
        let entry = test_entry("mirror.alias.org", "debian", MirrorKind::Structured);
        let mut config = test_config("/cache");
        config.aliases = vec![Alias {
            main: ClientHost::new("deb.debian.org".to_owned())
                .expect("valid host")
                .into_cache_host(),
            aliases: vec![ClientHost::new("mirror.alias.org".to_owned()).expect("valid host")],
        }];
        let paths = CachePaths::new(&config.cache_directory);
        let main = ClientHost::new("deb.debian.org".to_owned())
            .expect("valid host")
            .into_cache_host();
        let site = MirrorSite {
            host: &main,
            port: None,
            path: "debian",
        };
        assert_eq!(
            paths.mirror_dir(site),
            PathBuf::from("/cache/deb.debian.org/debian")
        );

        let units = classify_mirror(&entry, Vec::new(), &config);
        assert_eq!(units.len(), 8);
        for unit in &units {
            match unit {
                CleanupUnit::Reconcile(r) => {
                    assert_eq!(r.tree.root, paths.entry_dir(r.facet.cache_layout(), site));
                }
                CleanupUnit::ByHash(b) => {
                    assert_eq!(b.root, paths.entry_dir(b.layout, site));
                    let release_layout = if b.layout.is_flat() {
                        CacheLayout::Flat
                    } else {
                        CacheLayout::Dists
                    };
                    assert_eq!(b.release_dir, paths.entry_dir(release_layout, site));
                }
                CleanupUnit::Metadata(m) => {
                    assert_eq!(m.root, paths.entry_dir(m.layout, site));
                }
                CleanupUnit::Partials(p) => {
                    assert!(
                        p.root == paths.tmp_dir(CacheLayout::StructuredPool, site)
                            || p.root == paths.tmp_dir(CacheLayout::Flat, site),
                        "partials root {} is a layout tmp dir",
                        p.root.display()
                    );
                }
            }
        }
    }

    #[test]
    fn flat_row_skips_structured_units() {
        let entry = test_entry("apt.example.org", "apt", MirrorKind::Flat);
        let config = test_config("/cache");

        let units = classify_mirror(&entry, Vec::new(), &config);

        // No structured pool, dists metadata or dists by-hash unit: `kind`
        // latches one-way to Structured, so a Flat row cannot have those trees.
        assert_eq!(units.len(), 5);
        assert!(matches!(units[0], CleanupUnit::Partials(_)));
        assert!(matches!(units[1], CleanupUnit::Partials(_)));
        assert!(matches!(
            units[2],
            CleanupUnit::Reconcile(ReconcileUnit {
                facet: ReconcileFacet::FlatTree,
                tree: _,
                groups: _,
                policy: _,
            })
        ));
        assert!(matches!(
            units[3],
            CleanupUnit::Metadata(MetadataUnit {
                layout: CacheLayout::Flat,
                root: _,
                span: _,
            })
        ));
        assert!(matches!(
            units[4],
            CleanupUnit::ByHash(ByHashUnit {
                layout: CacheLayout::FlatByHash,
                root: _,
                release_dir: _,
                dist_gate: _,
                grace: _,
                backstop: _,
            })
        ));
    }

    #[test]
    fn hybrid_path_yields_owning_archive_root_group_first() {
        let entry = test_entry(
            "example.org",
            "api/packages/85/debian/pool/php-zts/main",
            MirrorKind::Flat,
        );
        let config = test_config("/cache");

        let units = classify_mirror(&entry, Vec::new(), &config);
        let flat_tree = flat_tree_unit(&units);

        assert_eq!(
            flat_tree.groups[0],
            SourceGroup {
                source: IndexSource::OriginPackages {
                    origin_rows_of: OriginOwner::ArchiveRoot {
                        root: "api/packages/85/debian".to_owned(),
                    },
                    keymap: KeymapSpec::RelpathUnderPrefix {
                        prefix: "pool/php-zts/main/".to_owned(),
                    },
                    cache_layout: CacheLayout::Flat,
                },
                owning: true,
            }
        );
    }

    #[test]
    fn flat_subpath_group_order_is_root_segment_then_colocated() {
        let entry = test_entry("apt.example.org", "apt/amd64", MirrorKind::Flat);
        let config = test_config("/cache");

        let units = classify_mirror(&entry, Vec::new(), &config);
        let flat_tree = flat_tree_unit(&units);

        assert_eq!(
            flat_tree.groups,
            vec![
                SourceGroup {
                    source: IndexSource::FlatPackages {
                        fetch: FlatFetch::RootSegment {
                            seg: "apt".to_owned(),
                            prefix: "amd64/".to_owned(),
                        },
                    },
                    owning: false,
                },
                SourceGroup {
                    source: IndexSource::FlatPackages {
                        fetch: FlatFetch::Colocated,
                    },
                    owning: false,
                },
            ]
        );
    }

    #[test]
    fn flat_single_segment_path_has_only_colocated_group() {
        let entry = test_entry("apt.example.org", "apt", MirrorKind::Flat);
        let config = test_config("/cache");

        let units = classify_mirror(&entry, Vec::new(), &config);
        let flat_tree = flat_tree_unit(&units);

        assert_eq!(
            flat_tree.groups,
            vec![SourceGroup {
                source: IndexSource::FlatPackages {
                    fetch: FlatFetch::Colocated,
                },
                owning: false,
            }]
        );
    }

    #[test]
    fn nested_paths_become_flat_tree_boundaries() {
        let entry = test_entry("deb.debian.org", "debian", MirrorKind::Structured);
        let config = test_config("/cache");
        let nested = vec!["debian/security".to_owned(), "debian/x".to_owned()];

        let units = classify_mirror(&entry, nested.clone(), &config);
        let flat_tree = flat_tree_unit(&units);

        assert_eq!(
            flat_tree.tree.walk,
            Walk::Recursive {
                skip_subdirs: &[SUBDIR_FLAT_BYHASH, SUBDIR_TMP],
                boundaries: nested,
            }
        );
    }

    // flat_root_split

    #[test]
    fn flat_root_split_computes_segment_and_prefix() {
        assert_eq!(
            flat_root_split("apt/amd64"),
            Some(("apt", "amd64/".to_owned()))
        );
        assert_eq!(flat_root_split("apt/"), None); // single segment after trim, no ancestor
        assert_eq!(flat_root_split("apt"), None); // single segment, no ancestor
        assert_eq!(
            flat_root_split("repo/dists/amd64/sub"),
            Some(("repo", "dists/amd64/sub/".to_owned()))
        );
    }
}
