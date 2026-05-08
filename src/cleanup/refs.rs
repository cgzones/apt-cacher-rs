use std::io::ErrorKind;
use std::path::Path;
use std::time::Duration;

use coarsetime::Clock;
use hashbrown::HashSet;
use tracing::{debug, error, warn};

use crate::cache_layout::CacheLayout;
use crate::database::MirrorEntry;
use crate::index_parser::{ByHashRef, HashAlgo, hex_decode_exact, parse_release_byhash_digests};
use crate::integrity::read_release_to_string;
use crate::metrics;
use crate::utils::probe_dir;
use crate::{AppState, RETENTION_TIME};

/// The set of by-hash digests referenced by a mirror's current
/// `Release`/`InRelease` files, for one by-hash directory. Built by
/// [`build_byhash_reference_set`]; consumed to decide which on-disk by-hash
/// files are still live.
pub(super) struct ByHashReferenceSet {
    pub(super) sha256: HashSet<[u8; 32]>,
    pub(super) sha512: HashSet<[u8; 64]>,
}

impl ByHashReferenceSet {
    /// Whether any current Release listed digests of `algo`. A by-hash file
    /// whose algorithm is *not* covered (e.g. a SHA512 file against a
    /// SHA256-only Debian Release) can't be reconciled and falls to the age
    /// backstop instead of being treated as unreferenced.
    pub(super) fn covers(&self, algo: HashAlgo) -> bool {
        match algo {
            HashAlgo::Sha256 => !self.sha256.is_empty(),
            HashAlgo::Sha512 => !self.sha512.is_empty(),
        }
    }

    /// Decode a by-hash filename (a bare lowercase hex digest) and report
    /// `(algorithm, whether-referenced)`. `None` when `name` is not a 64- or
    /// 128-hex digest (such an entry falls to the age backstop, never a
    /// reference deletion).
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
/// `<dist>[_<component>...]_Release`; flat releases sit at the flat root as
/// literal `Release`/`InRelease`. Detached signatures (`*.gpg`) are excluded -
/// they carry no checksum sections.
fn is_release_filename(name: &str, layout: CacheLayout) -> bool {
    if layout.is_flat() {
        name == "InRelease" || name == "Release"
    } else {
        name.ends_with("_InRelease") || name.ends_with("_Release")
    }
}

/// Build the union by-hash digest set for one by-hash directory from every
/// current `Release`/`InRelease` file in `release_dir`.
///
/// Returns `None` - signalling the caller to fall back to pure age-based
/// retention for the whole directory - when `release_dir` is absent, holds no
/// Release files, or ANY Release file fails to read/parse. The `dists/by-hash/`
/// tree is a union across all distributions, so a partial set (one dist's
/// `InRelease` missing) would falsely orphan that dist's files; we therefore
/// bail wholesale rather than reconcile against an incomplete set. An over-size
/// Release surfaces from [`read_release_to_string`] as `InvalidData` and is
/// handled here as a read failure.
///
/// `expected_dists` lists the distributions that must be covered for reference
/// mode to be sound (the mirror's active-origin dists). A dist whose flattened
/// `<dist>_{In,}Release` is *absent* from `release_dir` - not merely unreadable -
/// is otherwise invisible here, so without this check its by-hash files would be
/// orphaned; if any expected dist is missing we bail to age mode. Pass an empty
/// slice for the flat tree, which has a single root `{In,}Release` and no
/// per-dist union.
pub(super) async fn build_byhash_reference_set(
    release_dir: &Path,
    layout: CacheLayout,
    expected_dists: &[String],
) -> Option<ByHashReferenceSet> {
    let mut dir = match tokio::fs::read_dir(release_dir).await {
        Ok(d) => d,
        Err(err) if err.kind() == ErrorKind::NotFound => return None,
        Err(err) => {
            metrics::CACHE_IO_FAILURE.increment();
            error!(
                "Failed to read directory `{}`:  {err}",
                release_dir.display()
            );
            return None;
        }
    };

    let mut set = ByHashReferenceSet {
        sha256: HashSet::new(),
        sha512: HashSet::new(),
    };
    let mut found = false;
    // Distributions whose Release was present and parsed, to check against
    // `expected_dists` below. Only populated when there is something to check.
    let mut seen_dists: HashSet<String> = HashSet::new();

    loop {
        let entry = match dir.next_entry().await {
            Ok(Some(e)) => e,
            Ok(None) => break,
            Err(err) => {
                metrics::CACHE_IO_FAILURE.increment();
                error!(
                    "Failed to iterate directory `{}`:  {err}",
                    release_dir.display()
                );
                return None;
            }
        };
        let file_name = entry.file_name();
        let Some(name) = file_name.to_str() else {
            continue;
        };
        if !is_release_filename(name, layout) {
            continue;
        }
        found = true;
        if !expected_dists.is_empty() {
            // Recover the dist from the flattened `<dist>_{In,}Release` name
            // (the two suffixes are mutually exclusive: `<dist>_InRelease` does
            // not end with `_Release`).
            if let Some(dist) = name
                .strip_suffix("_InRelease")
                .or_else(|| name.strip_suffix("_Release"))
            {
                seen_dists.insert(dist.to_owned());
            }
        }
        let path = entry.path();
        let content = match read_release_to_string(&path).await {
            Ok(c) => c,
            Err(err) => {
                // Conservative: an unreadable or truncated Release means the
                // reference set would be incomplete, so abandon reference mode
                // for the whole directory and fall back to age-based retention.
                metrics::CACHE_IO_FAILURE.increment();
                warn!(
                    "Could not read Release file `{}` for by-hash reconciliation ({err}); falling back to age-based retention",
                    path.display()
                );
                return None;
            }
        };
        for digest in parse_release_byhash_digests(&content) {
            match digest {
                ByHashRef::Sha256(d) => {
                    set.sha256.insert(d);
                }
                ByHashRef::Sha512(d) => {
                    set.sha512.insert(d);
                }
            }
        }
    }

    // Reference mode reconciles the whole union `by-hash/` tree at once, so an
    // expected dist with no Release present would have its files orphaned. Bail
    // to age-based retention rather than reconcile against an incomplete union.
    for dist in expected_dists {
        if !seen_dists.contains(dist) {
            debug!(
                "by-hash reconciliation for `{}`: Release for distribution `{dist}` is absent; falling back to age-based retention",
                release_dir.display()
            );
            return None;
        }
    }

    found.then_some(set)
}

/// Distinct distributions of the mirror's *active* origins (seen within
/// `RETENTION_TIME`), used as the `expected_dists` completeness gate for
/// structured by-hash reconciliation. Stale dists are excluded so their by-hash
/// files age out normally.
///
/// Returns `None` on a DB error - the caller then forces age-based retention for
/// the structured tree this cycle rather than reconciling against a possibly
/// incomplete origin set (a missing still-active dist would otherwise let
/// reference mode orphan its by-hash files). `Some(vec![])` is a genuine "no
/// active origins", distinct from the error case.
pub(super) async fn active_origin_distributions(
    appstate: &AppState,
    mirror: &MirrorEntry,
) -> Option<Vec<String>> {
    let origins = match appstate
        .database
        .get_origins_by_mirror(&mirror.host, mirror.port(), &mirror.path)
        .await
    {
        Ok(o) => o,
        Err(err) => {
            metrics::DB_OPERATION_FAILED.increment();
            error!("Error looking up origins for by-hash cleanup:  {err}");
            return None;
        }
    };
    let now: Duration = Clock::now_since_epoch().into();
    let mut dists: Vec<String> = origins
        .into_iter()
        .filter(|origin| {
            Duration::from_secs(
                u64::try_from(origin.last_seen)
                    .expect("Database should never store negative timestamp"),
            ) + RETENTION_TIME
                > now
        })
        .map(|origin| origin.distribution)
        .collect();
    dists.sort_unstable();
    dists.dedup();
    Some(dists)
}

/// Whether a per-layout by-hash tree exists as a real directory. A hard I/O
/// error is logged (and counted) and treated as absent, so the expensive
/// Release reconciliation for that tree is skipped this cycle. `probe_dir`
/// reports a symlinked / non-directory root as absent with its own warning.
pub(super) async fn byhash_dir_present(path: &Path) -> bool {
    match probe_dir(path, "by-hash cleanup").await {
        Ok(present) => present,
        Err(err) => {
            metrics::CACHE_IO_FAILURE.increment();
            error!(
                "Failed to probe by-hash directory `{}`:  {err}",
                path.display()
            );
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fmt::Write as _;

    use super::*;
    use crate::index_parser::hex_encode;

    fn release_with_sha256(digests: &[[u8; 32]]) -> String {
        let mut s = String::from(
            "Origin: Test\nMD5Sum:\n cccccccccccccccccccccccccccccccc 9 ignored\nSHA256:\n",
        );
        for (i, d) in digests.iter().enumerate() {
            writeln!(
                s,
                " {} {} main/binary-amd64/file{i}",
                hex_encode(d),
                100 + i
            )
            .unwrap();
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
        assert!(is_release_filename(
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
        };
        set.sha256.insert(referenced);

        // 64-hex referenced / unreferenced.
        assert_eq!(
            set.classify(&hex_encode(&referenced)),
            Some((HashAlgo::Sha256, true))
        );
        assert_eq!(
            set.classify(&hex_encode(&[0x22u8; 32])),
            Some((HashAlgo::Sha256, false))
        );
        // Uppercase hex decodes to the same bytes -> still a hit.
        assert_eq!(
            set.classify(&hex_encode(&referenced).to_uppercase()),
            Some((HashAlgo::Sha256, true))
        );
        // 128-hex classifies as SHA512 (never in this set).
        assert_eq!(
            set.classify(&hex_encode(&[0x33u8; 64])),
            Some((HashAlgo::Sha512, false))
        );
        // Non-hex / wrong length -> None (routes to age backstop).
        assert_eq!(set.classify("not-a-digest"), None);
        assert_eq!(set.classify(&"z".repeat(64)), None);

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
        // A non-Release sibling is ignored.
        std::fs::write(dir.path().join("sid_main_binary-amd64_Packages.xz"), b"x")
            .expect("write pkg");

        let set = build_byhash_reference_set(dir.path(), CacheLayout::DistsByHash, &[])
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
        // Regression (#4): the structured `by-hash/` tree is a union across
        // dists, so an expected dist whose Release is *absent* (not unreadable)
        // would silently orphan its files. With `sid` present but `trixie`
        // expected-yet-absent, the builder must bail to age mode (None).
        let dir = tempfile::tempdir().expect("tempdir");
        let a = [0xaau8; 32];
        std::fs::write(dir.path().join("sid_InRelease"), release_with_sha256(&[a]))
            .expect("write sid");

        let expected = ["sid".to_owned(), "trixie".to_owned()];
        assert!(
            build_byhash_reference_set(dir.path(), CacheLayout::DistsByHash, &expected)
                .await
                .is_none(),
            "missing `trixie` Release must force age-based retention"
        );

        // With only `sid` expected -- the one present -- reference mode holds.
        let only_sid = ["sid".to_owned()];
        let set = build_byhash_reference_set(dir.path(), CacheLayout::DistsByHash, &only_sid)
            .await
            .expect("reference set built when every expected dist is present");
        assert!(set.sha256.contains(&a));
    }

    #[tokio::test]
    async fn build_reference_set_accepts_release_suffix_for_expected_dist() {
        // The `<dist>_Release` (non-Inline) form also satisfies the expected-dist
        // check: the suffix-strip must recognise it, not only `_InRelease`.
        let dir = tempfile::tempdir().expect("tempdir");
        let a = [0xccu8; 32];
        std::fs::write(dir.path().join("sid_Release"), release_with_sha256(&[a]))
            .expect("write sid");
        let expected = ["sid".to_owned()];
        assert!(
            build_byhash_reference_set(dir.path(), CacheLayout::DistsByHash, &expected)
                .await
                .is_some()
        );
    }

    #[tokio::test]
    async fn build_reference_set_empty_or_missing_is_none() {
        let dir = tempfile::tempdir().expect("tempdir");
        // Empty dir: no Release files.
        assert!(
            build_byhash_reference_set(dir.path(), CacheLayout::DistsByHash, &[])
                .await
                .is_none()
        );
        // Missing dir.
        assert!(
            build_byhash_reference_set(&dir.path().join("absent"), CacheLayout::DistsByHash, &[])
                .await
                .is_none()
        );
    }

    #[tokio::test]
    async fn build_reference_set_bails_on_unreadable_release() {
        let dir = tempfile::tempdir().expect("tempdir");
        // A *directory* named like a Release file: opening + read_to_string
        // fails (EISDIR), so the builder must bail to None (conservative
        // whole-dir fallback) rather than build a partial set.
        std::fs::create_dir(dir.path().join("sid_InRelease")).expect("mkdir");
        assert!(
            build_byhash_reference_set(dir.path(), CacheLayout::DistsByHash, &[])
                .await
                .is_none()
        );
    }
}
