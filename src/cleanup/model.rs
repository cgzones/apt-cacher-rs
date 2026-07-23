//! Pure cleanup data model: what to clean, against which index sources, and
//! how leftovers are retained. No I/O — classification and the sweep decision
//! are unit-testable truth tables.

use std::path::PathBuf;
use std::time::Duration;

use http::StatusCode;
use tracing::trace;

use crate::RETENTION_TIME;
use crate::cache_layout::{
    CacheLayout, SUBDIR_DISTS, SUBDIR_DISTS_BYHASH, SUBDIR_FLAT_BYHASH, SUBDIR_TMP,
};
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

/// Age threshold for a `.partial` scratch file, carried as the `Partials` units'
/// [`RetentionPolicy::AgeOnly`] span and applied by `partials::cleanup_tmp_dir`
/// (which keeps its own, longer backstop for foreign entries).
const PARTIALS_KEEP_SPAN: Duration = Duration::from_hours(3 * 24);

/// Which on-disk repository shape a [`CleanupUnit`] targets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum RepoFacet {
    /// Structured pool tree: `{host}/{path}/`, depth-1, basename-keyed.
    StructuredPool,
    /// Flat repository tree: `{host}/flat/{path}/`, recursive, relpath-keyed.
    FlatTree,
    /// Structured by-hash tree: `{host}/{path}/dists/.../by-hash/`.
    StructuredByHash,
    /// Flat by-hash tree: `{host}/flat/{path}/by-hash/`.
    FlatByHash,
    /// Structured dists-tree index metadata (age-only reap).
    StructuredMetadata,
    /// Flat-root index metadata (age-only reap).
    FlatMetadata,
    /// Stale partial-download temp files (age-only reap).
    Partials,
}

/// One independently-cleaned tree: which facet it is, where to scan, the
/// ordered index sources that reduce its candidate map, and how leftover
/// candidates are retained.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct CleanupUnit {
    pub facet: RepoFacet,
    pub tree: TreeSpec,
    pub groups: Vec<SourceGroup>,
    pub policy: RetentionPolicy,
}

/// Where a [`CleanupUnit`] scans on disk and how the walk is bounded. Consumed
/// verbatim by [`scan::scan_candidates`](crate::cleanup::scan::scan_candidates).
#[derive(Debug, PartialEq, Eq)]
pub(super) struct TreeSpec {
    /// On-disk root of the tree to scan.
    pub root: PathBuf,
    /// When `false`: depth-1 walk, basename keys, deb-named-directory warning.
    /// When `true`: recursive walk, relpath keys, honouring `skip_subdirs` and
    /// `boundaries`.
    pub recurse: bool,
    /// Sub-directory names to skip entirely during recursive traversal (e.g.
    /// `by-hash/` and `tmp/` for flat mirrors). Unused when `recurse` is `false`.
    pub skip_subdirs: &'static [&'static str],
    /// Mirror paths of registered siblings that live *inside* this mirror's
    /// path. When the recursive walk reaches a directory whose mirror-path
    /// equivalent hits one of these, the subtree is skipped (the nested mirror
    /// owns it and runs its own cleanup). Unused when `recurse` is `false`.
    pub boundaries: Vec<String>,
}

impl TreeSpec {
    /// A depth-1, unbounded walk of `root` — the shape every unit except
    /// `FlatTree` uses.
    fn shallow(root: PathBuf) -> Self {
        Self {
            root,
            recurse: false,
            skip_subdirs: &[],
            boundaries: Vec::new(),
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

/// A reference-set source that reduces a unit's candidate map.
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
    /// On-disk `Release` by-hash digest sets, gated on distribution
    /// completeness.
    LocalReleaseDigests {
        release_dir: PathBuf,
        dist_gate: DistGate,
    },
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

/// Whether an [`IndexSource::LocalReleaseDigests`] group requires every
/// expected active-origin distribution to be present before it counts as
/// complete.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum DistGate {
    /// Complete only when every active-origin distribution's `Release` is
    /// present and readable.
    ActiveOriginDists,
    /// No completeness gate (flat trees have no distributions).
    None,
}

/// How a *candidate-reconcile* unit (`StructuredPool` / `FlatTree`) retains
/// leftovers once its ordered [`SourceGroup`]s have run. This is the only input
/// [`decide_sweep`] takes a policy from: the by-hash and age-only facets never
/// reach it, so their retention is deliberately not representable here.
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

/// How leftover candidates (nothing referenced them) are retained after a
/// unit's groups have run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum RetentionPolicy {
    /// A candidate-reconcile unit; see [`ReconcilePolicy`].
    Reconcile(ReconcilePolicy),
    /// By-hash: a complete reference set keeps referenced digests and sweeps
    /// unreferenced-but-covered past `grace`; anything uncovered (or the
    /// reference set incomplete) sweeps past the `backstop`.
    ByHash { grace: Duration, backstop: Duration },
    /// Metadata, Partials: no reference source at all, pure age sweep.
    AgeOnly { span: Duration },
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
                    GroupOutcome::Complete | GroupOutcome::NotApplicable(_) => {}
                    GroupOutcome::FetchFailed(_) | GroupOutcome::ParseError => {
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
/// StructuredPool?, FlatTree, StructuredMetadata?, FlatMetadata,
/// StructuredByHash?, FlatByHash]`. The three `?` units are omitted for a
/// `MirrorKind::Flat` row: `kind` latches one-way to `Structured` (see
/// `upsert_mirror_get_id`), so a `Flat` row is guaranteed to have no
/// structured pool tree, dists tree, or dists by-hash tree on disk.
///
/// `nested` is the caller's pre-computed list of sibling mirror paths nested
/// under `entry.path` (`scan::derive_nested_paths`); it becomes the
/// [`FlatTree`](RepoFacet::FlatTree) unit's walk boundaries.
///
/// On-disk paths are computed via `entry.cache_path_with_aliases`/
/// `flat_root_path_with_aliases` (using `config.aliases`) rather than
/// reaching for `global_config()` (as the `cache_path` convenience method
/// does): `global_config()` panics outside a running daemon, and this
/// function must stay callable from a plain unit test.
pub(super) fn classify_mirror(
    entry: &MirrorEntry,
    nested: Vec<String>,
    config: &Config,
) -> Vec<CleanupUnit> {
    let is_flat = entry.kind() == MirrorKind::Flat;

    let cache_path = entry.cache_path_with_aliases(&config.aliases);
    let cache_root: PathBuf = config.cache_directory.join(&cache_path);
    let flat_root = entry.flat_root_path_with_aliases(&config.cache_directory, &config.aliases);

    let byhash_backstop = Duration::from_secs(24 * 60 * 60 * config.byhash_retention_days.get());

    let mut units = Vec::with_capacity(8);

    // Structured `tmp/` first, then flat `tmp/`.
    for root in [cache_root.join(SUBDIR_TMP), flat_root.join(SUBDIR_TMP)] {
        units.push(CleanupUnit {
            facet: RepoFacet::Partials,
            tree: TreeSpec::shallow(root),
            groups: Vec::new(),
            policy: RetentionPolicy::AgeOnly {
                span: PARTIALS_KEEP_SPAN,
            },
        });
    }

    if is_flat {
        trace!(
            "Skipping structured-pool cleanup for flat mirror {}",
            cache_path.display()
        );
    } else {
        units.push(CleanupUnit {
            facet: RepoFacet::StructuredPool,
            tree: TreeSpec::shallow(cache_root.clone()),
            groups: vec![SourceGroup {
                source: IndexSource::OriginPackages {
                    origin_rows_of: OriginOwner::SelfRow,
                    keymap: KeymapSpec::Basename,
                    cache_layout: CacheLayout::StructuredPool,
                },
                owning: false,
            }],
            policy: RetentionPolicy::Reconcile(ReconcilePolicy::ReferencedOrBail {
                grace: UNREFERENCED_KEEP_SPAN,
            }),
        });
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

    units.push(CleanupUnit {
        facet: RepoFacet::FlatTree,
        tree: TreeSpec {
            root: flat_root.clone(),
            recurse: true,
            skip_subdirs: &[SUBDIR_FLAT_BYHASH, SUBDIR_TMP],
            boundaries: nested,
        },
        groups: flat_groups,
        policy: RetentionPolicy::Reconcile(ReconcilePolicy::ReferencedOrAge {
            grace: UNREFERENCED_KEEP_SPAN,
            fallback: RETENTION_TIME,
        }),
    });

    if !is_flat {
        units.push(CleanupUnit {
            facet: RepoFacet::StructuredMetadata,
            tree: TreeSpec::shallow(cache_root.join(SUBDIR_DISTS)),
            groups: Vec::new(),
            policy: RetentionPolicy::AgeOnly {
                span: METADATA_KEEP_SPAN,
            },
        });
    }

    units.push(CleanupUnit {
        facet: RepoFacet::FlatMetadata,
        tree: TreeSpec::shallow(flat_root.clone()),
        groups: Vec::new(),
        policy: RetentionPolicy::AgeOnly {
            span: METADATA_KEEP_SPAN,
        },
    });

    if !is_flat {
        units.push(CleanupUnit {
            facet: RepoFacet::StructuredByHash,
            tree: TreeSpec::shallow(cache_root.join(SUBDIR_DISTS_BYHASH)),
            groups: vec![SourceGroup {
                source: IndexSource::LocalReleaseDigests {
                    release_dir: cache_root.join(SUBDIR_DISTS),
                    dist_gate: DistGate::ActiveOriginDists,
                },
                owning: false,
            }],
            policy: RetentionPolicy::ByHash {
                grace: UNREFERENCED_KEEP_SPAN,
                backstop: byhash_backstop,
            },
        });
    }

    units.push(CleanupUnit {
        facet: RepoFacet::FlatByHash,
        tree: TreeSpec::shallow(flat_root.join(SUBDIR_FLAT_BYHASH)),
        groups: vec![SourceGroup {
            source: IndexSource::LocalReleaseDigests {
                release_dir: flat_root,
                dist_gate: DistGate::None,
            },
            owning: false,
        }],
        policy: RetentionPolicy::ByHash {
            grace: UNREFERENCED_KEEP_SPAN,
            backstop: byhash_backstop,
        },
    });

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

    use crate::config::ClientHost;

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

    #[test]
    fn structured_row_emits_all_eight_units_in_order() {
        let entry = test_entry("deb.debian.org", "debian", MirrorKind::Structured);
        let config = test_config("/cache");

        let units = classify_mirror(&entry, Vec::new(), &config);

        assert_eq!(units.len(), 8);
        let facets: Vec<RepoFacet> = units.iter().map(|u| u.facet).collect();
        assert_eq!(
            facets,
            vec![
                RepoFacet::Partials,
                RepoFacet::Partials,
                RepoFacet::StructuredPool,
                RepoFacet::FlatTree,
                RepoFacet::StructuredMetadata,
                RepoFacet::FlatMetadata,
                RepoFacet::StructuredByHash,
                RepoFacet::FlatByHash,
            ]
        );

        assert_eq!(
            units[0].tree.root,
            PathBuf::from("/cache/deb.debian.org/debian/tmp")
        );
        assert_eq!(
            units[1].tree.root,
            PathBuf::from("/cache/deb.debian.org/flat/debian/tmp")
        );
        assert_eq!(
            units[2].tree.root,
            PathBuf::from("/cache/deb.debian.org/debian")
        );
        assert_eq!(
            units[2].groups,
            vec![SourceGroup {
                source: IndexSource::OriginPackages {
                    origin_rows_of: OriginOwner::SelfRow,
                    keymap: KeymapSpec::Basename,
                    cache_layout: CacheLayout::StructuredPool,
                },
                owning: false,
            }]
        );
        assert_eq!(
            units[3].tree.root,
            PathBuf::from("/cache/deb.debian.org/flat/debian")
        );
        assert_eq!(
            units[4].tree.root,
            PathBuf::from("/cache/deb.debian.org/debian/dists")
        );
        assert_eq!(
            units[5].tree.root,
            PathBuf::from("/cache/deb.debian.org/flat/debian")
        );
        assert_eq!(
            units[6].tree.root,
            PathBuf::from("/cache/deb.debian.org/debian/dists/by-hash")
        );
        assert_eq!(
            units[7].tree.root,
            PathBuf::from("/cache/deb.debian.org/flat/debian/by-hash")
        );

        assert_eq!(
            units[0].policy,
            RetentionPolicy::AgeOnly {
                span: PARTIALS_KEEP_SPAN
            }
        );
        assert_eq!(
            units[1].policy,
            RetentionPolicy::AgeOnly {
                span: PARTIALS_KEEP_SPAN
            }
        );
        assert_eq!(
            units[2].policy,
            RetentionPolicy::Reconcile(ReconcilePolicy::ReferencedOrBail {
                grace: UNREFERENCED_KEEP_SPAN
            })
        );
        assert_eq!(
            units[3].policy,
            RetentionPolicy::Reconcile(ReconcilePolicy::ReferencedOrAge {
                grace: UNREFERENCED_KEEP_SPAN,
                fallback: RETENTION_TIME
            })
        );
        assert_eq!(
            units[4].policy,
            RetentionPolicy::AgeOnly {
                span: METADATA_KEEP_SPAN
            }
        );
        assert_eq!(
            units[5].policy,
            RetentionPolicy::AgeOnly {
                span: METADATA_KEEP_SPAN
            }
        );
        assert_eq!(
            units[6].policy,
            RetentionPolicy::ByHash {
                grace: UNREFERENCED_KEEP_SPAN,
                backstop: Duration::from_secs(24 * 60 * 60 * config.byhash_retention_days.get())
            }
        );
        assert_eq!(
            units[7].policy,
            RetentionPolicy::ByHash {
                grace: UNREFERENCED_KEEP_SPAN,
                backstop: Duration::from_secs(24 * 60 * 60 * config.byhash_retention_days.get())
            }
        );
    }

    #[test]
    fn flat_row_skips_structured_units() {
        let entry = test_entry("apt.example.org", "apt", MirrorKind::Flat);
        let config = test_config("/cache");

        let units = classify_mirror(&entry, Vec::new(), &config);

        let facets: Vec<RepoFacet> = units.iter().map(|u| u.facet).collect();
        assert_eq!(
            facets,
            vec![
                RepoFacet::Partials,
                RepoFacet::Partials,
                RepoFacet::FlatTree,
                RepoFacet::FlatMetadata,
                RepoFacet::FlatByHash,
            ]
        );
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
        let flat_tree = units
            .iter()
            .find(|u| u.facet == RepoFacet::FlatTree)
            .expect("FlatTree unit present");

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
        let flat_tree = units
            .iter()
            .find(|u| u.facet == RepoFacet::FlatTree)
            .expect("FlatTree unit present");

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
        let flat_tree = units
            .iter()
            .find(|u| u.facet == RepoFacet::FlatTree)
            .expect("FlatTree unit present");

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
        let flat_tree = units
            .iter()
            .find(|u| u.facet == RepoFacet::FlatTree)
            .expect("FlatTree unit present");

        assert_eq!(flat_tree.tree.boundaries, nested);
        assert!(flat_tree.tree.recurse);
        assert_eq!(
            flat_tree.tree.skip_subdirs,
            &[SUBDIR_FLAT_BYHASH, SUBDIR_TMP]
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
