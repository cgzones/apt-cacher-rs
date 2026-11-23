//! Pure cleanup data model: what to clean, against which index sources, and
//! how leftovers are retained. No I/O — classification and the sweep decision
//! are unit-testable truth tables.

use std::path::PathBuf;
use std::time::Duration;

use http::StatusCode;
use tracing::trace;

use crate::cache_layout::CacheLayout;
use crate::cache_paths::{CachePaths, SUBDIR_FLAT_BYHASH, SUBDIR_TMP};
use crate::cleanup::fetch::FetchFailure;
use crate::cleanup::sweep::SpanTable;
use crate::config::Config;
use crate::database::MirrorEntry;
use crate::deb_mirror::{MirrorKind, flat_pool_archive_root};
use crate::limits::RETENTION_TIME;

/// Grace period for unreferenced cached deb files. Apt updates that bypass
/// the proxy register their origin lazily; this delay prevents a freshly
/// cached file from being wiped before its origin row is observed.
const UNREFERENCED_KEEP_SPAN: Duration = Duration::from_hours(3 * 24);

/// Retention span for volatile index metadata (`Release`/`InRelease`/`Packages*`
/// /...). These are refreshed while a distribution is in use (replaced on an
/// upstream change, mtime-touched on an unchanged revalidation), so aging
/// past this span marks the distribution as retired. While a retired dist's
/// `Release` lingers, by-hash cleanup keeps every digest it lists pinned.
/// Cached pdiff patches in `dists/` age out after [`PDIFF_KEEP_SPAN`] instead.
const METADATA_KEEP_SPAN: Duration = Duration::from_hours(90 * 24);

/// Retention span for a cached pdiff patch in a structured `dists/`
/// directory. A patch never changes under its name and is never
/// mtime-touched, so the span counts from its download. dak re-mints patch
/// names every run (~6 h) and deletes them after ~18 h, so two days keep
/// every patch through its upstream lifetime with margin while bounding the
/// disk the dead ones take. Carried as the structured `dists/`
/// [`MetadataUnit`]'s `pdiff_span`; the flat unit carries none.
const PDIFF_KEEP_SPAN: Duration = Duration::from_hours(2 * 24);

/// Age threshold for a `.partial` scratch file.
///
/// One day: a kept partial only pays off for a client retrying soon, while
/// every failed download leaves one behind that an unreliable (or hostile)
/// upstream can make as large as `max_object_size` -- disk usage that also
/// counts against the quota until it is reaped.
const PARTIALS_KEEP_SPAN: Duration = Duration::from_hours(24);

/// Which candidate-reconcile tree a [`ReconcileUnit`] targets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ReconcileFacet {
    /// Structured pool tree: `{host}/{path}/`, depth-1, basename-keyed.
    StructuredPool,
    /// Flat repository tree: `{host}/flat/{path}/`, recursive, relpath-keyed.
    FlatTree,
}

impl ReconcileFacet {
    /// The layout that places this facet's tree and keys its `cache_metadata`
    /// invalidation.
    pub(super) const fn cache_layout(self) -> CacheLayout {
        match self {
            Self::StructuredPool => CacheLayout::StructuredPool,
            Self::FlatTree => CacheLayout::Flat,
        }
    }
}

/// One independently-cleaned tree; the variant is its retention rule.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum CleanupUnit {
    /// Scan a tree into a candidate map, reduce it against ordered index
    /// sources, sweep what survives.
    Reconcile(ReconcileUnit),
    /// Sweep a by-hash tree against an on-disk `Release` digest set.
    ByHash(ByHashUnit),
    /// Age out stale index metadata in place.
    Metadata(MetadataUnit),
    /// Reap stale partial-download scratch files from one `tmp/` directory.
    Partials(PartialsUnit),
}

impl CleanupUnit {
    /// Whether running the unit fetches index files from the mirror. Cleanup
    /// drops these units for a mirror the allow-lists no longer permit,
    /// leaving its package trees as they are.
    #[must_use]
    pub(super) const fn fetches_indexes(&self) -> bool {
        match self {
            Self::Reconcile(_) => true,
            Self::ByHash(_) | Self::Metadata(_) | Self::Partials(_) => false,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(super) struct ReconcileUnit {
    pub facet: ReconcileFacet,
    pub tree: TreeSpec,
    pub groups: Vec<IndexSource>,
    pub policy: ReconcilePolicy,
}

/// The on-disk `Release` set that defines "referenced" follows from `layout`.
/// A complete reference set keeps referenced digests and sweeps
/// unreferenced-but-covered ones past `grace`; anything uncovered (or the
/// whole tree, when the reference set is incomplete) sweeps past `backstop`.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct ByHashUnit {
    pub layout: CacheLayout,
    pub root: PathBuf,
    pub grace: Duration,
    pub backstop: Duration,
}

impl ByHashUnit {
    /// The layout whose entry directory holds the `Release` files that
    /// reference this tree: the root of the same site's `Metadata` unit.
    pub(super) fn release_layout(&self) -> CacheLayout {
        if self.layout.is_flat() {
            CacheLayout::Flat
        } else {
            CacheLayout::Dists
        }
    }
}

/// A pure age sweep of `root`.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct MetadataUnit {
    pub layout: CacheLayout,
    pub root: PathBuf,
    pub span: Duration,
    /// The shorter span for a cached pdiff patch, if this tree can hold
    /// one: the structured `dists/` tree does, the flat tree does not (no
    /// flat patch is cached, and a flat file may carry such a name).
    pub pdiff_span: Option<Duration>,
}

/// A pure age reap of one `tmp/` directory. Carries no [`CacheLayout`]:
/// `tmp/` scratch files never enter the metadata store.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct PartialsUnit {
    pub root: PathBuf,
    pub span: Duration,
}

/// Where a [`ReconcileUnit`] scans on disk and how the walk is bounded.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct TreeSpec {
    pub root: PathBuf,
    pub walk: Walk,
}

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
        /// mirror's path. A directory at or inside one of these is not
        /// entered: the nested mirror owns it and runs its own cleanup.
        boundaries: Vec<String>,
    },
}

impl TreeSpec {
    fn shallow(root: PathBuf) -> Self {
        Self {
            root,
            walk: Walk::Shallow,
        }
    }
}

/// A reference-set source that reduces a reconcile unit's candidate map.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum IndexSource {
    /// Active origins of the row being cleaned, keyed by package basename.
    SelfOrigins,
    /// Active origins of a hybrid mirror's structured archive root, reducing
    /// its flat package tree by stripping the in-mirror prefix.
    ArchiveRoot { root: String, prefix: String },
    /// A flat-repository `Packages` fetch (co-located or root-segment).
    FlatPackages { fetch: FlatFetch },
}

/// Where a flat `Packages` index is fetched from.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum FlatFetch {
    /// Fetched from the same mirror path being cleaned.
    Colocated,
    /// Fetched from a flat-root segment above the mirror path (issue #162).
    RootSegment { seg: String, prefix: String },
}

/// How a [`ReconcileUnit`] retains leftovers once its ordered [`IndexSource`]s
/// have run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ReconcilePolicy {
    /// Structured pool: any group fetch/parse failure bails the whole unit
    /// (no sweep this cycle); otherwise sweep past `grace`.
    ReferencedOrBail { grace: Duration },
    /// Flat: sweep past `grace` when the reference set is usable per
    /// `decide_sweep` (note the quirk: a co-located parse error forces the
    /// fallback even when the root group completed); otherwise fall back to
    /// age-based `fallback`.
    ReferencedOrAge { grace: Duration, fallback: Duration },
}

impl ReconcilePolicy {
    pub(super) const fn grace(self) -> Duration {
        match self {
            Self::ReferencedOrBail { grace } | Self::ReferencedOrAge { grace, fallback: _ } => {
                grace
            }
        }
    }
}

/// Outcome of resolving one [`IndexSource`] against the candidate map.
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
    NoRow,
    /// A DB lookup needed to resolve the group failed.
    DbError,
    /// The gating row exists but has no active origins.
    NoActiveOrigins,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum SweepAction {
    /// Sweep leftover candidates on `spans`; `reason` selects the engine's
    /// diagnostics and completion summary.
    Sweep {
        spans: SpanTable,
        reason: SweepReason,
    },
    /// No sweep this cycle.
    Bail,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum SweepReason {
    /// At least one source reconciled (or none needed to): leftovers are
    /// genuinely unreferenced and reaped past the policy's short grace span.
    Grace,
    /// Every index source failed, so the reference set is incomplete and
    /// leftovers age out on the long fallback span instead.
    AgeFallback { primary: FetchFailure },
}

/// Final sweep decision for a unit from its policy and the ordered results of
/// the groups that ran.
pub(super) fn decide_sweep(policy: ReconcilePolicy, groups: &[GroupOutcome]) -> SweepAction {
    let grace_sweep = || SweepAction::Sweep {
        spans: SpanTable::uniform(policy.grace()),
        reason: SweepReason::Grace,
    };

    match policy {
        ReconcilePolicy::ReferencedOrBail { grace: _ } => {
            for outcome in groups {
                match outcome {
                    // A gate that legitimately did not apply (no row, no active
                    // origins) means there is no reference set to be had, which
                    // the grace sweep already handles.
                    GroupOutcome::Complete
                    | GroupOutcome::NotApplicable(
                        SkipReason::NoRow | SkipReason::NoActiveOrigins,
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
            let age_sweep = |primary| SweepAction::Sweep {
                spans: SpanTable::uniform(fallback),
                reason: SweepReason::AgeFallback { primary },
            };

            // The engine stops resolving at an archive-root group that
            // completed, so the last result is either that group -- which then
            // owns the whole reconciliation, hence Grace -- or the
            // always-present co-located probe.
            let Some((colocated, earlier)) = groups.split_last() else {
                return grace_sweep();
            };
            match colocated {
                GroupOutcome::Complete | GroupOutcome::NotApplicable(_) => grace_sweep(),
                // Quirk: a parse error falls back to age retention even when
                // the root index reduced fine.
                GroupOutcome::ParseError => age_sweep(FetchFailure {
                    status: StatusCode::BAD_GATEWAY,
                    upstream: None,
                }),
                // Only the root-segment group can have completed ahead of
                // the co-located probe; its reference set then stands.
                GroupOutcome::FetchFailed(primary) => {
                    if earlier.contains(&GroupOutcome::Complete) {
                        grace_sweep()
                    } else {
                        age_sweep(primary.clone())
                    }
                }
            }
        }
    }
}

/// Split a flat mirror path into its flat-repo root segment and the in-mirror
/// sub-path prefix (with a trailing `/`) that must be stripped from a root
/// `Packages` index's `Filename:` values before matching cached debs.
///
/// Returns `None` when the path has no ancestor segment distinct from itself
/// (single-segment, or trailing-slash-only like `"apt/"`) or starts with `/`,
/// so no flat-root fallback applies.
fn flat_root_split(mirror_path: &str) -> Option<(&str, String)> {
    let trimmed = mirror_path.trim_end_matches('/');
    let (head, rest) = trimmed.split_once('/')?;
    if head.is_empty() {
        return None;
    }
    // `trimmed` cannot end in `/`, so `rest` holds at least one non-slash
    // character and the trimmed prefix is never empty.
    let mut prefix = rest.trim_matches('/').to_owned();
    prefix.push('/');
    Some((head, prefix))
}

/// Classify one `mirrors_v2` row into the [`CleanupUnit`]s the engine runs
/// this cycle, in execution order.
///
/// The Metadata units precede the `ByHash` ones, so a `Release` retired this
/// cycle unpins its digests in the same cycle. The structured units are
/// omitted for a `MirrorKind::Flat` row: `kind` latches one-way to
/// `Structured`, so a `Flat` row has no structured pool, dists or dists
/// by-hash tree on disk.
///
/// `nested` holds the sibling mirror paths nested under `entry.path`; it
/// becomes the flat tree's walk boundaries.
///
/// Every unit root comes from [`CachePaths`], the same derivation the serve
/// path writes through.  Paths are computed from `config` rather than
/// `global_config()`, which panics outside a running daemon (unit tests).
pub(super) fn classify_mirror(
    entry: &MirrorEntry,
    nested: Vec<String>,
    config: &Config,
) -> Vec<CleanupUnit> {
    let is_flat = entry.kind() == MirrorKind::Flat;

    let paths = CachePaths::new(&config.cache_directory);
    let site = entry.site();

    let byhash_backstop = Duration::from_secs(24 * 60 * 60 * config.byhash_retention_days.get());

    let mut units = Vec::with_capacity(8);

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
            groups: vec![IndexSource::SelfOrigins],
            policy: ReconcilePolicy::ReferencedOrBail {
                grace: UNREFERENCED_KEEP_SPAN,
            },
        }));
    }

    let mut flat_groups = Vec::with_capacity(3);
    if let Some((root, prefix)) = flat_pool_archive_root(&entry.path) {
        flat_groups.push(IndexSource::ArchiveRoot {
            root: root.to_owned(),
            prefix,
        });
    }
    if let Some((seg, prefix)) = flat_root_split(&entry.path) {
        flat_groups.push(IndexSource::FlatPackages {
            fetch: FlatFetch::RootSegment {
                seg: seg.to_owned(),
                prefix,
            },
        });
    }
    flat_groups.push(IndexSource::FlatPackages {
        fetch: FlatFetch::Colocated,
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
            pdiff_span: Some(PDIFF_KEEP_SPAN),
        }));
    }

    let layout = CacheLayout::Flat;
    units.push(CleanupUnit::Metadata(MetadataUnit {
        layout,
        root: paths.entry_dir(layout, site),
        span: METADATA_KEEP_SPAN,
        pdiff_span: None,
    }));

    if !is_flat {
        let layout = CacheLayout::DistsByHash;
        units.push(CleanupUnit::ByHash(ByHashUnit {
            layout,
            root: paths.entry_dir(layout, site),
            grace: UNREFERENCED_KEEP_SPAN,
            backstop: byhash_backstop,
        }));
    }

    let layout = CacheLayout::FlatByHash;
    units.push(CleanupUnit::ByHash(ByHashUnit {
        layout,
        root: paths.entry_dir(layout, site),
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

    /// The `Grace` decision both test policies produce (their grace is 1s).
    fn grace() -> SweepAction {
        SweepAction::Sweep {
            spans: SpanTable::uniform(Duration::from_secs(1)),
            reason: SweepReason::Grace,
        }
    }

    /// The `AgeFallback` decision `AGE` produces (its fallback is 2s).
    fn age_back(primary: FetchFailure) -> SweepAction {
        SweepAction::Sweep {
            spans: SpanTable::uniform(Duration::from_secs(2)),
            reason: SweepReason::AgeFallback { primary },
        }
    }

    const BAIL: ReconcilePolicy = ReconcilePolicy::ReferencedOrBail {
        grace: Duration::from_secs(1),
    };
    const AGE: ReconcilePolicy = ReconcilePolicy::ReferencedOrAge {
        grace: Duration::from_secs(1),
        fallback: Duration::from_secs(2),
    };

    #[test]
    fn decide_sweep_referenced_or_bail() {
        use GroupOutcome::{Complete, FetchFailed, NotApplicable, ParseError};

        for (groups, expected) in [
            (vec![], grace()),
            (vec![Complete], grace()),
            (vec![NotApplicable(SkipReason::NoActiveOrigins)], grace()),
            (vec![FetchFailed(ff(404))], SweepAction::Bail),
            // The reference set is unknown rather than empty, so a grace
            // sweep could delete a deb the unread origins still reference.
            (vec![NotApplicable(SkipReason::DbError)], SweepAction::Bail),
            (vec![ParseError], SweepAction::Bail),
        ] {
            assert_eq!(decide_sweep(BAIL, &groups), expected, "{groups:?}");
        }
    }

    /// Group order is `[hybrid?, root?, colocated]`, colocated always last.
    #[test]
    fn decide_sweep_referenced_or_age() {
        use GroupOutcome::{Complete, FetchFailed, NotApplicable, ParseError};

        for (groups, expected) in [
            (vec![Complete], grace()),
            (vec![FetchFailed(ff(404))], age_back(ff(404))),
            (vec![ParseError], age_back(ff(502))),
            // A completed root group stands when the co-located fetch fails.
            (vec![Complete, FetchFailed(ff(404))], grace()),
            (
                vec![FetchFailed(ff(403)), FetchFailed(ff(404))],
                age_back(ff(404)),
            ),
            (
                vec![NotApplicable(SkipReason::NoRow), FetchFailed(ff(404))],
                age_back(ff(404)),
            ),
            (vec![ParseError, FetchFailed(ff(404))], age_back(ff(404))),
            // Quirk: a co-located parse error ignores the completed root.
            (vec![Complete, ParseError], age_back(ff(502))),
            // A failed hybrid group does not prejudice a completed root.
            (
                vec![FetchFailed(ff(404)), Complete, FetchFailed(ff(404))],
                grace(),
            ),
        ] {
            assert_eq!(decide_sweep(AGE, &groups), expected, "{groups:?}");
        }
    }

    // classify_mirror

    use crate::cache_paths::MirrorSite;
    use crate::config::ClientHost;

    fn test_entry(host: &str, path: &str, kind: MirrorKind) -> MirrorEntry {
        MirrorEntry::new_for_test(
            ClientHost::new(host).expect("valid host"),
            None,
            path.to_owned(),
            kind,
        )
    }

    fn test_config(cache_dir: &str) -> Config {
        let mut config = Config::default();
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

    #[test]
    fn structured_row_emits_all_eight_units_in_order() {
        let entry = test_entry("deb.debian.org", "debian", MirrorKind::Structured);
        let config = test_config("/cache");
        let backstop = Duration::from_secs(24 * 60 * 60 * config.byhash_retention_days.get());

        let units = classify_mirror(&entry, Vec::new(), &config);

        // The roots are spelled out rather than derived so this test pins the
        // on-disk positions themselves.
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
                    groups: vec![IndexSource::SelfOrigins],
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
                    groups: vec![IndexSource::FlatPackages {
                        fetch: FlatFetch::Colocated,
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
                    pdiff_span: Some(PDIFF_KEEP_SPAN),
                }),
                CleanupUnit::Metadata(MetadataUnit {
                    layout: CacheLayout::Flat,
                    root: PathBuf::from("/cache/deb.debian.org/flat/debian"),
                    span: METADATA_KEEP_SPAN,
                    pdiff_span: None,
                }),
                CleanupUnit::ByHash(ByHashUnit {
                    layout: CacheLayout::DistsByHash,
                    root: PathBuf::from("/cache/deb.debian.org/debian/dists/by-hash"),
                    grace: UNREFERENCED_KEEP_SPAN,
                    backstop,
                }),
                CleanupUnit::ByHash(ByHashUnit {
                    layout: CacheLayout::FlatByHash,
                    root: PathBuf::from("/cache/deb.debian.org/flat/debian/by-hash"),
                    grace: UNREFERENCED_KEEP_SPAN,
                    backstop,
                }),
            ]
        );
    }

    #[test]
    fn unit_roots_are_the_serve_path_entry_dirs_of_the_site() {
        // Rows are canonical (the alias' main host) by the time cleanup reads
        // them.
        let entry = test_entry("deb.debian.org", "debian", MirrorKind::Structured);
        let config = test_config("/cache");
        let paths = CachePaths::new(&config.cache_directory);
        let main = ClientHost::new("deb.debian.org")
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
                    let release_dir = paths.entry_dir(b.release_layout(), site);
                    assert!(
                        units.iter().any(
                            |u| matches!(u, CleanupUnit::Metadata(m) if m.root == release_dir)
                        ),
                        "{} is a Metadata unit's root",
                        release_dir.display()
                    );
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
                pdiff_span: None,
            })
        ));
        assert!(matches!(
            units[4],
            CleanupUnit::ByHash(ByHashUnit {
                layout: CacheLayout::FlatByHash,
                root: _,
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
            flat_tree.groups,
            vec![
                IndexSource::ArchiveRoot {
                    root: "api/packages/85/debian".to_owned(),
                    prefix: "pool/php-zts/main/".to_owned(),
                },
                IndexSource::FlatPackages {
                    fetch: FlatFetch::RootSegment {
                        seg: "api".to_owned(),
                        prefix: "packages/85/debian/pool/php-zts/main/".to_owned(),
                    },
                },
                IndexSource::FlatPackages {
                    fetch: FlatFetch::Colocated,
                },
            ]
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
                IndexSource::FlatPackages {
                    fetch: FlatFetch::RootSegment {
                        seg: "apt".to_owned(),
                        prefix: "amd64/".to_owned(),
                    },
                },
                IndexSource::FlatPackages {
                    fetch: FlatFetch::Colocated,
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
            vec![IndexSource::FlatPackages {
                fetch: FlatFetch::Colocated,
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
        assert_eq!(flat_root_split(""), None);
        assert_eq!(
            flat_root_split("repo/dists/amd64/sub"),
            Some(("repo", "dists/amd64/sub/".to_owned()))
        );
    }

    #[test]
    fn flat_root_split_normalises_stray_slashes_and_rejects_a_leading_one() {
        // Repeated separators collapse into the same segment/prefix pair, and
        // the prefix always ends in exactly one `/` (it is stripped from
        // `Filename:` values, so a doubled or missing slash would match nothing).
        assert_eq!(
            flat_root_split("apt//amd64//"),
            Some(("apt", "amd64/".to_owned()))
        );
        // A leading `/` would make the flat-repo root segment empty.
        assert_eq!(flat_root_split("/apt/amd64"), None);
    }
}
