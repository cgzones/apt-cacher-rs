use std::path::Path;
use std::time::Duration;

use coarsetime::Clock;
use hashbrown::{HashMap, HashSet};
use tracing::{debug, warn};

use crate::cache_layout::CacheLayout;
use crate::cache_walk::{AnomalyLevel, DirFailure, EntryKind, WalkContext, WalkOutcome, Walker};
use crate::database::OriginEntry;
use crate::error::ErrorReport;
use crate::fs_open::count_cache_failure;
use crate::index_parser::{ByHashRef, HashAlgo, hex_decode_exact, parse_release_byhash_digests};
use crate::integrity::read_release_to_string;
use crate::log_once::Logged;
use crate::{metrics, warn_once_or_debug};

use super::engine::CleanupUnitError;

/// The set of by-hash digests referenced by a mirror's current
/// `Release`/`InRelease` files, for one by-hash directory.
pub(super) struct ByHashReferenceSet {
    pub(super) sha256: HashSet<[u8; 32]>,
    pub(super) sha512: HashSet<[u8; 64]>,
    pub(super) complete_sha256: bool,
    pub(super) complete_sha512: bool,
}

impl ByHashReferenceSet {
    /// Whether every distribution has usable digests of `algo`. A by-hash file
    /// whose algorithm is *not* covered (e.g. a SHA512 file against a
    /// SHA256-only Debian Release) can't be reconciled and falls to the age
    /// backstop instead of being treated as unreferenced.
    pub(super) fn covers(&self, algo: HashAlgo) -> bool {
        match algo {
            HashAlgo::Sha256 => self.complete_sha256,
            HashAlgo::Sha512 => self.complete_sha512,
        }
    }

    /// Decode a by-hash filename (a bare hex digest) and report
    /// `(algorithm, whether-referenced)`. `None` when `name` is not a 64- or
    /// 128-hex digest; such an entry falls to the age backstop.
    pub(super) fn classify(&self, name: &str) -> Option<(HashAlgo, bool)> {
        match name.len() {
            64 => {
                let digest = hex_decode_exact::<32>(name)?;
                Some((HashAlgo::Sha256, self.sha256.contains(&digest)))
            }
            128 => {
                let digest = hex_decode_exact::<64>(name)?;
                Some((HashAlgo::Sha512, self.sha512.contains(&digest)))
            }
            _ => None,
        }
    }
}

/// Whether `name` is a top-level `Release`/`InRelease` index for `layout`.
///
/// Structured releases are flattened as `<dist>_InRelease` /
/// `<dist>_Release`; flat releases sit at the flat root as
/// literal `Release`/`InRelease`. Detached signatures (`*.gpg`) are excluded -
/// they carry no checksum sections.
fn is_release_filename(name: &str, layout: CacheLayout) -> bool {
    if layout.is_flat() {
        name == "InRelease" || name == "Release"
    } else {
        name.split_once('_')
            .is_some_and(|(dist, leaf)| !dist.is_empty() && matches!(leaf, "Release" | "InRelease"))
    }
}

static RELEASE_WALK: WalkContext = WalkContext {
    what: "a Release directory",
    dir_failure: DirFailure::Abort("falling back to age-based retention for its by-hash tree"),
    entry_failure: "falling back to age-based retention for its by-hash tree",
    non_regular: "ignoring it for by-hash reconciliation (a Release entry forces age-based retention)",
    anomalies: AnomalyLevel::Warn,
};

/// Build the union by-hash digest set for one by-hash directory from every
/// current `Release`/`InRelease` file in `release_dir`.
///
/// Returns `None` - the caller falls back to pure age-based retention for the
/// whole directory - when `release_dir` is absent, holds no Release files, or
/// ANY Release file fails to read/parse. The `dists/by-hash/` tree is a union
/// across all distributions, so a partial set would falsely orphan the
/// missing dist's files.
///
/// `expected_dists` lists the distributions that must be covered (the
/// mirror's active-origin dists): a dist whose Release is *absent* is
/// otherwise invisible here. Pass an empty slice for the flat tree.
pub(super) async fn build_byhash_reference_set(
    cache_root: &Path,
    release_dir: &Path,
    layout: CacheLayout,
    expected_dists: &[&str],
) -> Option<ByHashReferenceSet> {
    let mut walker = Walker::below(cache_root, release_dir, &RELEASE_WALK, ());

    let mut set = ByHashReferenceSet {
        sha256: HashSet::new(),
        sha512: HashSet::new(),
        complete_sha256: false,
        complete_sha512: false,
    };
    // Every parsed Release contributes algorithm coverage, including the flat
    // layout's empty distribution key. Also checked against `expected_dists`.
    let mut coverage: HashMap<String, (bool, bool)> = HashMap::new();

    while let Some(entry) = walker.next().await {
        let Some(name) = entry.name().to_str() else {
            continue;
        };
        if !is_release_filename(name, layout) {
            continue;
        }
        if entry.kind() != EntryKind::File {
            if entry.kind() == EntryKind::Dir {
                entry.report_unexpected("falling back to age-based retention for its by-hash tree");
            }
            return None;
        }
        let path = entry.path();
        let content = match read_release_to_string(&path).await {
            Ok(c) => c,
            Err(err) => {
                // Only a failed syscall counts: an oversized or non-UTF-8
                // Release (an errno-less `InvalidData` from the reader) is a
                // content problem, and one removed since the walk listed it
                // is a concurrent removal.
                if err.raw_os_error().is_some() && err.kind() != std::io::ErrorKind::NotFound {
                    count_cache_failure(&err);
                }
                warn!(
                    "Failed to read Release file `{}` for by-hash reconciliation; falling back to age-based retention:  {}",
                    path.display(),
                    ErrorReport(&err)
                );
                return None;
            }
        };
        let parsed = match parse_release_byhash_digests(&content, |digest| match digest {
            ByHashRef::Sha256(d) => {
                set.sha256.insert(d);
            }
            ByHashRef::Sha512(d) => {
                set.sha512.insert(d);
            }
        }) {
            Ok(parsed) => parsed,
            Err(reason) => {
                warn!(
                    "Failed to parse Release file `{}` for by-hash reconciliation; falling back to age-based retention: {reason}",
                    path.display()
                );
                return None;
            }
        };
        let dist = if layout.is_flat() {
            ""
        } else {
            name.split_once('_').expect("top-level Release name").0
        };
        let algorithms = coverage.entry(dist.to_owned()).or_default();
        algorithms.0 |= parsed.sha256;
        algorithms.1 |= parsed.sha512;
    }

    if walker.io_failures() != 0 {
        return None;
    }
    match walker.finish() {
        WalkOutcome::Complete => {}
        // Returned before the Release-less warn below: an unreadable
        // directory was already logged by the walker.
        WalkOutcome::RootMissing | WalkOutcome::Aborted { .. } => return None,
    }

    for &dist in expected_dists {
        if !coverage.contains_key(dist) {
            debug!(
                "by-hash reconciliation for `{}`: Release for distribution `{dist}` is absent; falling back to age-based retention",
                release_dir.display()
            );
            return None;
        }
    }

    if coverage.is_empty() {
        // The by-hash tree exists but no Release names it, so the whole tree
        // drops to the age backstop instead of the 3-day grace.
        warn_once_or_debug!(
            "No Release files in `{}` for by-hash reconciliation; falling back to age-based retention",
            release_dir.display()
        );
        return None;
    }
    set.complete_sha256 = coverage.values().all(|algorithms| algorithms.0);
    set.complete_sha512 = coverage.values().all(|algorithms| algorithms.1);
    Some(set)
}

/// Distinct distributions of the mirror's *active* origins, the
/// `expected_dists` completeness gate for structured by-hash reconciliation.
/// Stale dists are excluded so their by-hash files age out normally.
///
/// `None` origins means the read failed; it propagates so the caller forces
/// age-based retention rather than reconciling against a possibly incomplete
/// origin set. `Some(vec![])` is a genuine "no active origins".
#[must_use]
pub(super) fn active_origin_distributions(origins: Option<&[OriginEntry]>) -> Option<Vec<&str>> {
    let now: Duration = Clock::now_since_epoch().into();
    let mut dists: Vec<&str> = origins?
        .iter()
        .filter(|origin| origin.is_active(now))
        .map(|origin| origin.distribution.as_str())
        .collect();
    dists.sort_unstable();
    dists.dedup();
    Some(dists)
}

/// Whether a per-layout by-hash tree exists as a real directory, by `lstat`
/// so a hostile symlink cannot redirect the walk outside the cache tree. A
/// symlinked or non-directory root is absent with a warning; a hard I/O
/// error abandons the unit.
pub(super) async fn byhash_dir_present(path: &Path) -> Result<bool, CleanupUnitError> {
    match tokio::fs::symlink_metadata(path).await {
        Ok(md) if md.file_type().is_dir() => Ok(true),
        Ok(md) if md.file_type().is_symlink() => {
            metrics::CACHE_NON_REGULAR.increment();
            warn!(
                "Skipping by-hash cleanup because root is a symlink: `{}`",
                path.display()
            );
            Ok(false)
        }
        Ok(_) => {
            warn!(
                "Skipping by-hash cleanup because root is not a directory: `{}`",
                path.display()
            );
            Ok(false)
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(err) => Err(CleanupUnitError(Logged::cache_io_failure(format_args!(
            "Failed to probe by-hash directory `{}`; abandoning its by-hash cleanup this cycle:  {}",
            path.display(),
            ErrorReport(&err)
        )))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ClientHost;
    use crate::limits::{MAX_RELEASE_SIZE, RETENTION_TIME};
    use crate::{index_parser::hex_encode, metrics, swrite};

    fn origin(distribution: &str, age: Duration) -> OriginEntry {
        let now = Clock::now_since_epoch().as_secs();
        OriginEntry::new_for_test(
            ClientHost::new("deb.example.org").expect("valid host"),
            "debian".to_owned(),
            distribution.to_owned(),
            i64::try_from(now.saturating_sub(age.as_secs())).expect("in range"),
        )
    }

    #[test]
    fn active_origin_distributions_sorts_dedups_and_drops_stale() {
        let fresh = Duration::from_mins(1);
        let stale = RETENTION_TIME + Duration::from_mins(1);
        let origins = [
            origin("trixie", fresh),
            origin("sid", fresh),
            origin("sid", fresh),
            origin("retired", stale),
        ];
        assert_eq!(
            active_origin_distributions(Some(&origins)),
            Some(vec!["sid", "trixie"])
        );
    }

    #[test]
    fn active_origin_distributions_distinguishes_unread_from_empty() {
        assert_eq!(active_origin_distributions(None), None);
        assert_eq!(active_origin_distributions(Some(&[])), Some(Vec::new()));
    }

    fn release_with_sha256(digests: &[[u8; 32]]) -> String {
        let mut s = String::from(
            "Origin: Test\nMD5Sum:\n cccccccccccccccccccccccccccccccc 9 ignored\nSHA256:\n",
        );
        for (i, d) in digests.iter().enumerate() {
            swrite!(
                s,
                " {} {} main/binary-amd64/file{i}\n",
                hex_encode(d),
                100 + i
            );
        }
        s
    }

    #[test]
    fn is_release_filename_structured_and_flat() {
        // Structured: flattened `<dist>_{In,}Release`, no detached sigs.
        assert!(is_release_filename(
            "sid_InRelease",
            CacheLayout::DistsByHash
        ));
        assert!(is_release_filename("sid_Release", CacheLayout::DistsByHash));
        assert!(!is_release_filename(
            "trixie_main_binary-amd64_Release",
            CacheLayout::DistsByHash
        ));
        assert!(!is_release_filename(
            "sid_Release.gpg",
            CacheLayout::DistsByHash
        ));
        assert!(!is_release_filename(
            "sid_main_binary-amd64_Packages.xz",
            CacheLayout::DistsByHash
        ));
        assert!(!is_release_filename("by-hash", CacheLayout::DistsByHash));
        // Flat: literal names at the flat root.
        assert!(is_release_filename("InRelease", CacheLayout::FlatByHash));
        assert!(is_release_filename("Release", CacheLayout::FlatByHash));
        assert!(!is_release_filename(
            "sid_InRelease",
            CacheLayout::FlatByHash
        ));
    }

    #[test]
    fn reference_set_classify_and_covers() {
        let referenced = [0x11u8; 32];
        let mut set = ByHashReferenceSet {
            sha256: HashSet::new(),
            sha512: HashSet::new(),
            complete_sha256: true,
            complete_sha512: false,
        };
        set.sha256.insert(referenced);

        assert_eq!(
            set.classify(&hex_encode(&referenced)),
            Some((HashAlgo::Sha256, true))
        );
        assert_eq!(
            set.classify(&hex_encode(&[0x22u8; 32])),
            Some((HashAlgo::Sha256, false))
        );
        // Uppercase hex decodes to the same bytes.
        assert_eq!(
            set.classify(&hex_encode(&referenced).to_uppercase()),
            Some((HashAlgo::Sha256, true))
        );
        assert_eq!(
            set.classify(&hex_encode(&[0x33u8; 64])),
            Some((HashAlgo::Sha512, false))
        );
        assert_eq!(set.classify("not-a-digest"), None);
        assert_eq!(set.classify(&"z".repeat(64)), None);

        assert!(set.covers(HashAlgo::Sha256));
        assert!(!set.covers(HashAlgo::Sha512));
    }

    #[tokio::test]
    async fn malformed_sibling_release_abandons_reference_cleanup() {
        let dir = tempfile::tempdir().expect("tempdir");
        let valid = release_with_sha256(&[[0xaa; 32]]);
        std::fs::write(dir.path().join("stable_Release"), &valid).expect("stable");
        for malformed in [
            "Origin: No checksums\n".to_owned(),
            "SHA256:\n".to_owned(),
            "SHA256:\n broken-digest 123 Packages\n".to_owned(),
            format!("{valid} broken-digest 123 Packages\n"),
            format!("SHA256:\n {} nope Packages\n", hex_encode(&[0xbb; 32])),
            format!("SHA256:\n {} 1 Packages extra\n", hex_encode(&[0xbb; 32])),
        ] {
            std::fs::write(dir.path().join("sid_Release"), malformed).expect("sid");
            assert!(
                build_byhash_reference_set(
                    dir.path(),
                    dir.path(),
                    CacheLayout::DistsByHash,
                    &["stable", "sid"]
                )
                .await
                .is_none(),
                "a valid sibling cannot hide malformed references"
            );
        }
    }

    #[tokio::test]
    async fn unreadable_release_sibling_cannot_be_hidden_by_a_valid_release() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            dir.path().join("sid_Release"),
            release_with_sha256(&[[0xaa; 32]]),
        )
        .expect("Release");
        std::os::unix::fs::symlink(dir.path().join("absent"), dir.path().join("sid_InRelease"))
            .expect("symlink");
        assert!(
            build_byhash_reference_set(dir.path(), dir.path(), CacheLayout::DistsByHash, &["sid"])
                .await
                .is_none(),
            "unreadable signed sibling forces age retention"
        );
    }

    #[tokio::test]
    async fn algorithm_coverage_requires_every_distribution() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            dir.path().join("sid_Release"),
            release_with_sha256(&[[0xaa; 32]]),
        )
        .expect("sid");
        std::fs::write(dir.path().join("stable_InRelease"), format!("-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA512\n\nSHA512:\n {} 1 Packages\n-----BEGIN PGP SIGNATURE-----\nSHA256:\n bad\n", hex_encode(&[0xbb; 64]))).expect("stable");
        // Component Release files legitimately lack checksums and cannot establish coverage.
        std::fs::write(
            dir.path().join("sid_main_binary-amd64_Release"),
            "Archive: sid\n",
        )
        .expect("component");
        let set = build_byhash_reference_set(
            dir.path(),
            dir.path(),
            CacheLayout::DistsByHash,
            &["sid", "stable"],
        )
        .await
        .expect("valid distributions");
        assert!(!set.covers(HashAlgo::Sha256));
        assert!(!set.covers(HashAlgo::Sha512));
        std::fs::write(
            dir.path().join("stable_Release"),
            release_with_sha256(&[[0xcc; 32]]),
        )
        .expect("additional complete algorithm");
        let set = build_byhash_reference_set(dir.path(), dir.path(), CacheLayout::DistsByHash, &[])
            .await
            .expect("set");
        assert!(set.covers(HashAlgo::Sha256));
        assert!(!set.covers(HashAlgo::Sha512));
    }

    #[tokio::test]
    async fn build_reference_set_unions_releases() {
        let dir = tempfile::tempdir().expect("tempdir");
        let a = [0xaau8; 32];
        let b = [0xbbu8; 32];
        std::fs::write(dir.path().join("sid_InRelease"), release_with_sha256(&[a]))
            .expect("write sid");
        std::fs::write(
            dir.path().join("trixie_InRelease"),
            release_with_sha256(&[b]),
        )
        .expect("write trixie");
        std::fs::write(dir.path().join("sid_main_binary-amd64_Packages.xz"), b"x")
            .expect("write pkg");

        let set = build_byhash_reference_set(dir.path(), dir.path(), CacheLayout::DistsByHash, &[])
            .await
            .expect("reference set built");
        assert!(set.sha256.contains(&a));
        assert!(set.sha256.contains(&b));
        assert_eq!(set.sha256.len(), 2);
        assert!(set.covers(HashAlgo::Sha256));
        assert!(!set.covers(HashAlgo::Sha512));
    }

    #[tokio::test]
    async fn build_reference_set_bails_when_expected_dist_absent() {
        let dir = tempfile::tempdir().expect("tempdir");
        let a = [0xaau8; 32];
        std::fs::write(dir.path().join("sid_InRelease"), release_with_sha256(&[a]))
            .expect("write sid");

        let expected = ["sid", "trixie"];
        assert!(
            build_byhash_reference_set(dir.path(), dir.path(), CacheLayout::DistsByHash, &expected)
                .await
                .is_none(),
            "missing `trixie` Release must force age-based retention"
        );

        let only_sid = ["sid"];
        let set =
            build_byhash_reference_set(dir.path(), dir.path(), CacheLayout::DistsByHash, &only_sid)
                .await
                .expect("reference set built when every expected dist is present");
        assert!(set.sha256.contains(&a));
    }

    #[tokio::test]
    async fn build_reference_set_empty_or_missing_is_none() {
        let dir = tempfile::tempdir().expect("tempdir");
        assert!(
            build_byhash_reference_set(dir.path(), dir.path(), CacheLayout::DistsByHash, &[])
                .await
                .is_none()
        );
        assert!(
            build_byhash_reference_set(
                dir.path(),
                &dir.path().join("absent"),
                CacheLayout::DistsByHash,
                &[]
            )
            .await
            .is_none()
        );
    }

    #[tokio::test]
    async fn build_reference_set_bails_on_a_non_utf8_release_uncounted() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("sid_InRelease"), [0xff, 0xfe, 0xfd]).expect("write");
        let io_failure = metrics::CACHE_IO_FAILURE.get();
        assert!(
            build_byhash_reference_set(dir.path(), dir.path(), CacheLayout::DistsByHash, &[])
                .await
                .is_none()
        );
        assert_eq!(metrics::CACHE_IO_FAILURE.get(), io_failure);
    }

    #[tokio::test]
    async fn build_reference_set_bails_on_oversized_release() {
        let dir = tempfile::tempdir().expect("tempdir");
        // A valid sibling must not rescue the set.
        std::fs::write(
            dir.path().join("stable_InRelease"),
            release_with_sha256(&[[0xcc; 32]]),
        )
        .expect("valid Release");
        let path = dir.path().join("sid_InRelease");
        std::fs::File::create(&path)
            .expect("create oversized Release")
            .set_len(MAX_RELEASE_SIZE.get() + 1)
            .expect("size oversized Release");
        assert!(read_release_to_string(&path).await.is_err());
        assert!(
            build_byhash_reference_set(dir.path(), dir.path(), CacheLayout::DistsByHash, &[])
                .await
                .is_none()
        );
    }

    #[tokio::test]
    async fn byhash_dir_present_counts_a_symlinked_root() {
        let dir = tempfile::tempdir().expect("tempdir");
        let real = dir.path().join("by-hash");
        let link = dir.path().join("link");
        let file = dir.path().join("file");
        std::fs::create_dir(&real).expect("mkdir");
        std::os::unix::fs::symlink(&real, &link).expect("symlink");
        std::fs::write(&file, b"x").expect("write");

        let non_regular = metrics::CACHE_NON_REGULAR.get();
        for (path, present) in [
            (&real, true),
            (&dir.path().join("absent"), false),
            (&file, false),
        ] {
            let got = byhash_dir_present(path).await.expect("probed");
            assert_eq!(got, present, "{}", path.display());
        }
        assert_eq!(metrics::CACHE_NON_REGULAR.get(), non_regular);

        let got = byhash_dir_present(&link).await.expect("probed");
        assert!(!got, "a symlinked root is absent");
        assert_eq!(metrics::CACHE_NON_REGULAR.get(), non_regular + 1);
    }
}
