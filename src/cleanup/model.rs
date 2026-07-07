//! Pure cleanup data model: what to clean, against which index sources, and
//! how leftovers are retained. No I/O — classification and the sweep decision
//! are unit-testable truth tables.

use std::path::{Path, PathBuf};
use std::time::Duration;

use http::StatusCode;
use log::trace;

use crate::RETENTION_TIME;
use crate::cache_layout::{
    CacheLayout, SUBDIR_DISTS, SUBDIR_DISTS_BYHASH, SUBDIR_FLAT_BYHASH, SUBDIR_TMP,
};
use crate::cleanup::packages::FetchFailure;
use crate::config::Config;
use crate::database::MirrorEntry;
use crate::deb_mirror::{MirrorKind, flat_pool_archive_root};

use super::{METADATA_KEEP_SPAN, UNREFERENCED_KEEP_SPAN};

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

/// Where a [`CleanupUnit`] scans on disk and how the walk is bounded.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct TreeSpec {
    pub root: PathBuf,
    pub recurse: bool,
    pub skip_subdirs: &'static [&'static str],
    pub boundaries: Vec<String>,
}

/// One source *description* applied to the unit's candidate map. Per-origin
/// fan-out happens at resolution time in the engine; sources within a group
/// are conjunctive (all must be resolved to consider the group's candidates
/// reduced).
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

/// Whether a [`IndexSource::LocalReleaseDigests`] group requires every
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

/// How leftover candidates (nothing referenced them) are retained after a
/// unit's groups have run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum RetentionPolicy {
    /// Structured pool: any group fetch/parse failure bails the whole unit
    /// (no sweep this cycle); otherwise sweep past `grace`
    /// (`UNREFERENCED_KEEP_SPAN`).
    ReferencedOrBail { grace: Duration },
    /// Flat: at least one group parsed OK sweeps past `grace`; all groups
    /// failed falls back to age-based `fallback` (`RETENTION_TIME`).
    ReferencedOrAge { grace: Duration, fallback: Duration },
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
/// results.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum SweepAction {
    /// Sweep leftover candidates past the policy's short grace span.
    Grace,
    /// Sweep leftover candidates past the policy's age-based fallback span,
    /// carrying the primary fetch failure and (if attempted and it failed
    /// with a different status) the root-segment failure for the warn
    /// suffix.
    AgeFallback {
        primary: FetchFailure,
        root_failed: Option<(String, FetchFailure)>,
    },
    /// Bail: no sweep this cycle.
    Bail,
}

/// Final sweep decision for a unit from its policy and the ordered results of
/// the groups that ran. The whole flat-cascade fallback table lives here —
/// replacing the RootFirst/FlatTimeFallback state threading of the previous
/// implementation.
pub(super) fn decide_sweep(policy: &RetentionPolicy, groups: &[GroupResult]) -> SweepAction {
    match policy {
        RetentionPolicy::ReferencedOrBail { grace: _ } => {
            for g in groups {
                match &g.outcome {
                    GroupOutcome::Complete | GroupOutcome::NotApplicable(_) => {}
                    GroupOutcome::FetchFailed(_) | GroupOutcome::ParseError => {
                        return SweepAction::Bail;
                    }
                }
            }
            SweepAction::Grace
        }
        RetentionPolicy::ReferencedOrAge {
            grace: _,
            fallback: _,
        } => {
            // An owning group that completed ended reconciliation (the engine
            // stops early), so its presence as the last result means Grace.
            if let Some(last) = groups.last()
                && last.owning
                && matches!(last.outcome, GroupOutcome::Complete)
            {
                return SweepAction::Grace;
            }
            // Otherwise the last group is the always-present co-located probe.
            let Some(colocated) = groups.last() else {
                return SweepAction::Grace;
            };
            let root = groups
                .iter()
                .rev()
                .skip(1)
                .find(|g| g.root_seg.is_some() && !g.owning);
            match &colocated.outcome {
                GroupOutcome::Complete | GroupOutcome::NotApplicable(_) => SweepAction::Grace,
                // A parse error falls back to age retention even when the
                // root index reduced fine — preserved from the previous
                // implementation (reconcile.rs colocated-Err arm ignored
                // root_first). See truth-table test.
                GroupOutcome::ParseError => SweepAction::AgeFallback {
                    primary: FetchFailure {
                        status: StatusCode::BAD_GATEWAY,
                        upstream: None,
                    },
                    root_failed: None,
                },
                GroupOutcome::FetchFailed(primary) => match root.map(|g| (&g.outcome, g)) {
                    Some((GroupOutcome::Complete, _)) => SweepAction::Grace,
                    Some((GroupOutcome::FetchFailed(rf), g)) => SweepAction::AgeFallback {
                        primary: primary.clone(),
                        root_failed: g.root_seg.clone().map(|seg| (seg, rf.clone())),
                    },
                    _ => SweepAction::AgeFallback {
                        primary: primary.clone(),
                        root_failed: None,
                    },
                },
            }
        }
        // Reference-set availability is expressed through candidate classes
        // (covered ⇒ grace span, uncovered ⇒ backstop), not the action.
        RetentionPolicy::ByHash {
            grace: _,
            backstop: _,
        }
        | RetentionPolicy::AgeOnly { span: _ } => SweepAction::Grace,
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

/// Age threshold the Partials units' policy documents, matching
/// `cleanup_tmp_dir`'s `.partial`-file threshold (`partials.rs`) — the more
/// common case there (a zero-byte or stale `.partial`) rather than the
/// defensive, longer foreign-entry threshold. Documentation only: the engine
/// still delegates the actual sweep to `cleanup_tmp_dir`, whose own two-tier
/// policy is unaffected by this field.
const PARTIALS_KEEP_SPAN: Duration = Duration::from_hours(3 * 24);

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
    let cache_root: PathBuf = [config.cache_directory.as_path(), cache_path.as_path()]
        .iter()
        .collect();
    let flat_root = entry.flat_root_path_with_aliases(&config.cache_directory, &config.aliases);

    let byhash_backstop = Duration::from_secs(24 * 60 * 60 * config.byhash_retention_days.get());

    let mut units = Vec::with_capacity(8);

    units.push(CleanupUnit {
        facet: RepoFacet::Partials,
        tree: TreeSpec {
            root: [cache_root.as_path(), Path::new(SUBDIR_TMP)]
                .iter()
                .collect(),
            recurse: false,
            skip_subdirs: &[],
            boundaries: Vec::new(),
        },
        groups: Vec::new(),
        policy: RetentionPolicy::AgeOnly {
            span: PARTIALS_KEEP_SPAN,
        },
    });

    units.push(CleanupUnit {
        facet: RepoFacet::Partials,
        tree: TreeSpec {
            root: flat_root.join(SUBDIR_TMP),
            recurse: false,
            skip_subdirs: &[],
            boundaries: Vec::new(),
        },
        groups: Vec::new(),
        policy: RetentionPolicy::AgeOnly {
            span: PARTIALS_KEEP_SPAN,
        },
    });

    if is_flat {
        trace!(
            "Skipping structured-pool cleanup for flat mirror {}",
            cache_path.display()
        );
    } else {
        units.push(CleanupUnit {
            facet: RepoFacet::StructuredPool,
            tree: TreeSpec {
                root: cache_root.clone(),
                recurse: false,
                skip_subdirs: &[],
                boundaries: Vec::new(),
            },
            groups: vec![SourceGroup {
                source: IndexSource::OriginPackages {
                    origin_rows_of: OriginOwner::SelfRow,
                    keymap: KeymapSpec::Basename,
                    cache_layout: CacheLayout::StructuredPool,
                },
                owning: false,
            }],
            policy: RetentionPolicy::ReferencedOrBail {
                grace: UNREFERENCED_KEEP_SPAN,
            },
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
        policy: RetentionPolicy::ReferencedOrAge {
            grace: UNREFERENCED_KEEP_SPAN,
            fallback: RETENTION_TIME,
        },
    });

    if !is_flat {
        units.push(CleanupUnit {
            facet: RepoFacet::StructuredMetadata,
            tree: TreeSpec {
                root: [cache_root.as_path(), Path::new(SUBDIR_DISTS)]
                    .iter()
                    .collect(),
                recurse: false,
                skip_subdirs: &[],
                boundaries: Vec::new(),
            },
            groups: Vec::new(),
            policy: RetentionPolicy::AgeOnly {
                span: METADATA_KEEP_SPAN,
            },
        });
    }

    units.push(CleanupUnit {
        facet: RepoFacet::FlatMetadata,
        tree: TreeSpec {
            root: flat_root.clone(),
            recurse: false,
            skip_subdirs: &[],
            boundaries: Vec::new(),
        },
        groups: Vec::new(),
        policy: RetentionPolicy::AgeOnly {
            span: METADATA_KEEP_SPAN,
        },
    });

    if !is_flat {
        units.push(CleanupUnit {
            facet: RepoFacet::StructuredByHash,
            tree: TreeSpec {
                root: [cache_root.as_path(), Path::new(SUBDIR_DISTS_BYHASH)]
                    .iter()
                    .collect(),
                recurse: false,
                skip_subdirs: &[],
                boundaries: Vec::new(),
            },
            groups: vec![SourceGroup {
                source: IndexSource::LocalReleaseDigests {
                    release_dir: [cache_root.as_path(), Path::new(SUBDIR_DISTS)]
                        .iter()
                        .collect(),
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
        tree: TreeSpec {
            root: flat_root.join(SUBDIR_FLAT_BYHASH),
            recurse: false,
            skip_subdirs: &[],
            boundaries: Vec::new(),
        },
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

    fn owning(outcome: GroupOutcome) -> GroupResult {
        GroupResult {
            owning: true,
            root_seg: None,
            outcome,
        }
    }

    const BAIL: RetentionPolicy = RetentionPolicy::ReferencedOrBail {
        grace: Duration::from_secs(1),
    };
    const AGE: RetentionPolicy = RetentionPolicy::ReferencedOrAge {
        grace: Duration::from_secs(1),
        fallback: Duration::from_secs(2),
    };
    const BYHASH: RetentionPolicy = RetentionPolicy::ByHash {
        grace: Duration::from_secs(1),
        backstop: Duration::from_secs(2),
    };
    const AGE_ONLY: RetentionPolicy = RetentionPolicy::AgeOnly {
        span: Duration::from_secs(1),
    };

    // ReferencedOrBail (structured pool)

    #[test]
    fn bail_no_groups_is_grace() {
        assert_eq!(decide_sweep(&BAIL, &[]), SweepAction::Grace);
    }

    #[test]
    fn bail_complete_is_grace() {
        assert_eq!(
            decide_sweep(&BAIL, &[gr(GroupOutcome::Complete)]),
            SweepAction::Grace
        );
    }

    #[test]
    fn bail_fetch_failed_bails() {
        assert_eq!(
            decide_sweep(&BAIL, &[gr(GroupOutcome::FetchFailed(ff(404)))]),
            SweepAction::Bail
        );
    }

    #[test]
    fn bail_parse_error_bails() {
        assert_eq!(
            decide_sweep(&BAIL, &[gr(GroupOutcome::ParseError)]),
            SweepAction::Bail
        );
    }

    // ReferencedOrAge (flat; group order = [hybrid?, root?, colocated], colocated ALWAYS last)

    #[test]
    fn age_owning_complete_is_grace() {
        assert_eq!(
            decide_sweep(&AGE, &[owning(GroupOutcome::Complete)]),
            SweepAction::Grace
        );
    }

    #[test]
    fn age_colocated_only_complete_is_grace() {
        assert_eq!(
            decide_sweep(&AGE, &[gr(GroupOutcome::Complete)]),
            SweepAction::Grace
        );
    }

    #[test]
    fn age_colocated_only_fetch_failed_falls_back() {
        assert_eq!(
            decide_sweep(&AGE, &[gr(GroupOutcome::FetchFailed(ff(404)))]),
            SweepAction::AgeFallback {
                primary: ff(404),
                root_failed: None
            }
        );
    }

    #[test]
    fn age_colocated_only_parse_error_falls_back_with_bad_gateway() {
        assert_eq!(
            decide_sweep(&AGE, &[gr(GroupOutcome::ParseError)]),
            SweepAction::AgeFallback {
                primary: ff(502),
                root_failed: None
            }
        );
    }

    #[test]
    fn age_root_complete_is_grace() {
        assert_eq!(
            decide_sweep(
                &AGE,
                &[
                    root("apt", GroupOutcome::Complete),
                    gr(GroupOutcome::FetchFailed(ff(404)))
                ]
            ),
            SweepAction::Grace
        );
    }

    #[test]
    fn age_root_failed_and_colocated_failed_falls_back_with_root_context() {
        assert_eq!(
            decide_sweep(
                &AGE,
                &[
                    root("apt", GroupOutcome::FetchFailed(ff(403))),
                    gr(GroupOutcome::FetchFailed(ff(404)))
                ]
            ),
            SweepAction::AgeFallback {
                primary: ff(404),
                root_failed: Some(("apt".to_owned(), ff(403)))
            }
        );
    }

    #[test]
    fn age_root_not_applicable_falls_back_without_root_context() {
        assert_eq!(
            decide_sweep(
                &AGE,
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
            SweepAction::AgeFallback {
                primary: ff(404),
                root_failed: None
            }
        );
    }

    #[test]
    fn age_root_parse_error_falls_back_without_root_context() {
        assert_eq!(
            decide_sweep(
                &AGE,
                &[
                    root("apt", GroupOutcome::ParseError),
                    gr(GroupOutcome::FetchFailed(ff(404)))
                ]
            ),
            SweepAction::AgeFallback {
                primary: ff(404),
                root_failed: None
            }
        );
    }

    /// Quirk row (invariant 3): a co-located parse error falls back to age
    /// retention even when the root index reduced fine, reproducing
    /// `reconcile.rs:837-848` — the colocated-Err arm there ignores
    /// `root_first` entirely.
    #[test]
    fn age_colocated_parse_error_ignores_completed_root() {
        assert_eq!(
            decide_sweep(
                &AGE,
                &[
                    root("apt", GroupOutcome::Complete),
                    gr(GroupOutcome::ParseError)
                ]
            ),
            SweepAction::AgeFallback {
                primary: ff(502),
                root_failed: None
            }
        );
    }

    #[test]
    fn age_failed_strict_defers_without_prejudice() {
        assert_eq!(
            decide_sweep(
                &AGE,
                &[
                    owning(GroupOutcome::FetchFailed(ff(404))),
                    root("apt", GroupOutcome::Complete),
                    gr(GroupOutcome::FetchFailed(ff(404)))
                ]
            ),
            SweepAction::Grace
        );
    }

    // ByHash

    #[test]
    fn byhash_complete_is_always_grace() {
        assert_eq!(
            decide_sweep(&BYHASH, &[gr(GroupOutcome::Complete)]),
            SweepAction::Grace
        );
    }

    #[test]
    fn byhash_db_error_is_always_grace() {
        assert_eq!(
            decide_sweep(
                &BYHASH,
                &[gr(GroupOutcome::NotApplicable(SkipReason::DbError))]
            ),
            SweepAction::Grace
        );
    }

    // AgeOnly

    #[test]
    fn age_only_no_groups_is_grace() {
        assert_eq!(decide_sweep(&AGE_ONLY, &[]), SweepAction::Grace);
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
            RetentionPolicy::ReferencedOrBail {
                grace: UNREFERENCED_KEEP_SPAN
            }
        );
        assert_eq!(
            units[3].policy,
            RetentionPolicy::ReferencedOrAge {
                grace: UNREFERENCED_KEEP_SPAN,
                fallback: RETENTION_TIME
            }
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

    // flat_root_split (moved from reconcile.rs)

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
