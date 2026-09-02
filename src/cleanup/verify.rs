use std::borrow::Cow;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;

use crate::fs_open::nofollow_nonblock_options;
use crate::index_parser::{HashAlgo, byhash_digest_for_algo, hash_open_file, hex_encode};
use crate::metrics;
use crate::xattr_helpers::{self, XattrValue};

/// Xattr recording a successful cleanup digest verification, persisted as
/// `user.apt_cacher_rs.cleanup_verified` = `"{ino}:{size}:{algo}:{digest-hex}"`.
///
/// A later cycle skips re-hashing when inode, size, algorithm, and expected
/// digest all still match — the daily full-cache re-read otherwise scales
/// with total cache size instead of churn. Binding the expected digest
/// means an index update that changes the expected content invalidates the
/// marker automatically; binding `(ino, size)` means any re-download
/// (temp file + rename, so a fresh inode) invalidates it too.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct CleanupMarker {
    ino: u64,
    size: u64,
    algo: HashAlgo,
    digest: Vec<u8>,
}

impl CleanupMarker {
    fn new(ino: u64, size: u64, algo: HashAlgo, expected: &[u8]) -> Self {
        Self {
            ino,
            size,
            algo,
            digest: expected.to_vec(),
        }
    }

    /// Whether the marker was stamped for exactly this file identity and
    /// expected digest.
    fn matches(&self, ino: u64, size: u64, algo: HashAlgo, expected: &[u8]) -> bool {
        let Self {
            ino: my_ino,
            size: my_size,
            algo: my_algo,
            digest,
        } = self;
        *my_ino == ino && *my_size == size && *my_algo == algo && digest == expected
    }
}

impl XattrValue for CleanupMarker {
    const KEY: &'static str = "user.apt_cacher_rs.cleanup_verified";
    const LABEL: &'static str = "cleanup verification marker";
    // Without any log a per-file stamp failure is indistinguishable from
    // working memoization, and every cycle silently re-hashes the whole cache.
    const WRITE_FAILURE_CONSEQUENCE: &'static str =
        "digest verification is not memoized and every cleanup cycle re-hashes this file";

    fn discard_gate() -> &'static AtomicBool {
        static GATE: AtomicBool = AtomicBool::new(false);
        &GATE
    }

    fn parse(raw: &str) -> Option<Self> {
        let mut parts = raw.split(':');
        let ino = parts.next()?.parse().ok()?;
        let size = parts.next()?.parse().ok()?;
        let algo = HashAlgo::parse(parts.next()?)?;
        let digest = byhash_digest_for_algo(algo, parts.next()?)?;
        if parts.next().is_some() {
            return None;
        }
        Some(Self {
            ino,
            size,
            algo,
            digest,
        })
    }

    fn render(&self) -> Cow<'_, str> {
        let Self {
            ino,
            size,
            algo,
            digest,
        } = self;
        Cow::Owned(format!(
            "{ino}:{size}:{}:{}",
            algo.as_str(),
            hex_encode(digest)
        ))
    }
}

/// Whether `file` carries a verified marker matching the current identity
/// and expected digest. Any read failure or mismatch counts as "not
/// verified" (the caller re-hashes and re-stamps); a malformed marker is
/// scrubbed by the xattr layer.
fn has_valid_marker(
    file: &std::fs::File,
    path: &Path,
    ino: u64,
    size: u64,
    algo: HashAlgo,
    expected: &[u8],
) -> bool {
    xattr_helpers::read::<CleanupMarker>(file, path)
        .is_some_and(|marker| marker.matches(ino, size, algo, expected))
}

/// Stamp the verified marker after a successful digest match. Best-effort:
/// a failure (logged once by the xattr layer, e.g. a filesystem without
/// xattr support) just means the next cycle re-hashes.
fn stamp_marker(
    file: &std::fs::File,
    path: &Path,
    ino: u64,
    size: u64,
    algo: HashAlgo,
    expected: &[u8],
) {
    xattr_helpers::write(file, path, &CleanupMarker::new(ino, size, algo, expected));
}

/// Outcome of verifying a cache file against an expected digest.
#[derive(Debug)]
pub(super) enum Verdict {
    /// Computed digest equals the expected one.
    Match,
    /// Computed digest differs from the expected one and the underlying file
    /// did not change inode/size during hashing. `size` is the on-disk size
    /// observed before hashing, which the caller bills to the eviction.
    Mismatch { computed: Vec<u8>, size: u64 },
    /// The file's `(inode, size)` changed between hash start and finish, so a
    /// concurrent writer raced us; the cleanup leaves the file alone.
    Raced,
    /// The path is no longer a regular file — a type swap since the scan
    /// classified it. Counted as `CACHE_NON_REGULAR` here; the caller retains
    /// the entry without verifying it.
    NonRegular,
    /// Open/read failed; cleanup leaves the file alone.
    IoError(std::io::Error),
}

/// Blocking digest-and-compare with an inode/size race check after hashing.
/// Runs on the blocking pool via [`verify_cache_file`].
pub(super) fn verify_file_sync(path: &Path, algo: HashAlgo, expected: &[u8]) -> Verdict {
    use std::os::unix::fs::MetadataExt as _;

    let mut file = match nofollow_nonblock_options().read(true).open(path) {
        Ok(f) => f,
        Err(err) => {
            metrics::CACHE_IO_FAILURE.increment();
            return Verdict::IoError(err);
        }
    };
    let pre_meta = match file.metadata() {
        Ok(m) if m.file_type().is_file() => m,
        Ok(_) => {
            metrics::CACHE_NON_REGULAR.increment();
            return Verdict::NonRegular;
        }
        Err(err) => {
            metrics::CACHE_IO_FAILURE.increment();
            return Verdict::IoError(err);
        }
    };
    let pre_ino = pre_meta.ino();
    let pre_size = pre_meta.len();

    // Memoized fast path: verified in an earlier cycle and unchanged since
    // (same inode/size, same expected digest) — skip the full read+hash.
    if has_valid_marker(&file, path, pre_ino, pre_size, algo, expected) {
        metrics::CLEANUP_CHECKSUM_SKIPS.increment();
        return Verdict::Match;
    }

    let computed = match algo {
        HashAlgo::Sha256 => match hash_open_file::<sha2::Sha256>(&mut file) {
            Ok(h) => h,
            Err(err) => {
                metrics::CACHE_IO_FAILURE.increment();
                return Verdict::IoError(err);
            }
        },
        HashAlgo::Sha512 => match hash_open_file::<sha2::Sha512>(&mut file) {
            Ok(h) => h,
            Err(err) => {
                metrics::CACHE_IO_FAILURE.increment();
                return Verdict::IoError(err);
            }
        },
    };

    if computed.as_slice() == expected {
        // Only stamp when the file is still the one we hashed — a swap
        // mid-hash must not mark the *new* content as verified.
        match std::fs::symlink_metadata(path) {
            Ok(post_meta) if post_meta.ino() == pre_ino && post_meta.len() == pre_size => {
                stamp_marker(&file, path, pre_ino, pre_size, algo, expected);
            }
            Ok(_) | Err(_) => {}
        }
        return Verdict::Match;
    }

    // Race check: a fresh download finishing mid-hash either replaces the
    // file via rename (different inode) or rewrites it in place (size change).
    // Either way our digest is for content no longer at `path`, so bail.
    // Use `symlink_metadata` (lstat): a hostile symlink planted at `path`
    // after the open could otherwise point at a file whose inode/size
    // happen to match `pre_ino` / `pre_size`, masking the race.  lstat
    // compares the symlink itself, so a swap is always detected.
    //
    // A stat failure here (e.g. another cleanup task already unlinked the
    // file, or EACCES) is treated like the pre-hash stat failure: bump and
    // return `Verdict::IoError` so the caller logs and retains.  Falling
    // through to `Verdict::Mismatch` would emit a false checksum-corruption
    // warn and then attempt a doomed `remove_file` on the missing path.
    match std::fs::symlink_metadata(path) {
        Ok(post_meta) if post_meta.ino() != pre_ino || post_meta.len() != pre_size => {
            Verdict::Raced
        }
        Ok(_) => Verdict::Mismatch {
            computed,
            size: pre_size,
        },
        Err(err) => {
            metrics::CACHE_IO_FAILURE.increment();
            Verdict::IoError(err)
        }
    }
}

pub(super) async fn verify_cache_file(path: PathBuf, algo: HashAlgo, expected: Vec<u8>) -> Verdict {
    match tokio::task::spawn_blocking(move || verify_file_sync(&path, algo, &expected)).await {
        Ok(v) => v,
        Err(join_err) => Verdict::IoError(std::io::Error::other(join_err)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_file_sync_match_and_mismatch() {
        use sha2::Digest as _;
        use std::io::Write as _;

        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("cache.deb");
        let payload = b"hello apt-cacher-rs world";
        {
            let mut f = std::fs::File::create(&path).expect("create");
            f.write_all(payload).expect("write");
        }

        let expected_sha256 = sha2::Sha256::digest(payload).to_vec();
        assert!(matches!(
            verify_file_sync(&path, HashAlgo::Sha256, &expected_sha256),
            Verdict::Match
        ));

        let wrong: Vec<u8> = vec![0u8; 32];
        let v = verify_file_sync(&path, HashAlgo::Sha256, &wrong);
        let Verdict::Mismatch { computed, size } = v else {
            unreachable!("expected Mismatch verdict, got {v:?}")
        };
        assert_eq!(computed, expected_sha256);
        assert_eq!(size, payload.len() as u64, "size is billed to the eviction");

        let expected_sha512 = sha2::Sha512::digest(payload).to_vec();
        assert!(matches!(
            verify_file_sync(&path, HashAlgo::Sha512, &expected_sha512),
            Verdict::Match
        ));
    }

    #[test]
    fn verify_file_sync_io_error_on_missing_path() {
        let dir = tempfile::tempdir().expect("tempdir");
        let missing = dir.path().join("does_not_exist");
        assert!(matches!(
            verify_file_sync(&missing, HashAlgo::Sha256, &[0u8; 32]),
            Verdict::IoError(_)
        ));
    }

    #[test]
    fn verified_marker_memoizes_and_binds_expected_digest() {
        use std::io::Write as _;

        use sha2::Digest as _;

        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("cache.deb");
        let payload = b"marker memoization payload";
        {
            let mut f = std::fs::File::create(&path).expect("create");
            f.write_all(payload).expect("write");
        }
        let expected = sha2::Sha256::digest(payload).to_vec();

        assert!(matches!(
            verify_file_sync(&path, HashAlgo::Sha256, &expected),
            Verdict::Match
        ));

        // The marker may be missing on filesystems without user-xattr
        // support (stamping is best-effort); only assert the fast path
        // where it actually stuck.
        let file = std::fs::File::open(&path).expect("open");
        let stamped = xattr_helpers::read::<CleanupMarker>(&file, &path).is_some();
        if stamped {
            // The counter is process-global and other unit tests in this
            // binary bump it concurrently, so assert the delta as a lower
            // bound.
            let before = metrics::CLEANUP_CHECKSUM_SKIPS.get();
            assert!(matches!(
                verify_file_sync(&path, HashAlgo::Sha256, &expected),
                Verdict::Match
            ));
            assert!(
                metrics::CLEANUP_CHECKSUM_SKIPS.get() > before,
                "second verification should take the memoized fast path"
            );
        }

        // A different expected digest invalidates the marker: the file is
        // re-hashed and mismatches for real.
        let wrong: Vec<u8> = vec![0u8; 32];
        assert!(matches!(
            verify_file_sync(&path, HashAlgo::Sha256, &wrong),
            Verdict::Mismatch { .. }
        ));
    }

    #[test]
    fn cleanup_marker_parse_and_render() {
        let digest = [0xabu8; 32];
        let marker = CleanupMarker::new(42, 1234, HashAlgo::Sha256, &digest);
        let rendered = marker.render();
        assert_eq!(rendered, format!("42:1234:SHA256:{}", hex_encode(&digest)));
        assert_eq!(CleanupMarker::parse(&rendered), Some(marker));

        let sha512 = [0x11u8; 64];
        let marker = CleanupMarker::new(7, 0, HashAlgo::Sha512, &sha512);
        assert_eq!(
            CleanupMarker::parse(&marker.render()).as_ref(),
            Some(&marker)
        );
        assert!(marker.matches(7, 0, HashAlgo::Sha512, &sha512));
        assert!(!marker.matches(8, 0, HashAlgo::Sha512, &sha512));
        assert!(!marker.matches(7, 1, HashAlgo::Sha512, &sha512));
        assert!(!marker.matches(7, 0, HashAlgo::Sha256, &sha512));
        assert!(!marker.matches(7, 0, HashAlgo::Sha512, &[0x22u8; 64]));

        let hex = hex_encode(&digest);
        assert!(CleanupMarker::parse("").is_none());
        assert!(CleanupMarker::parse("42:1234:SHA256").is_none());
        assert!(CleanupMarker::parse(&format!("x:1234:SHA256:{hex}")).is_none());
        assert!(CleanupMarker::parse(&format!("42:1234:MD5:{hex}")).is_none());
        // Digest length must match the algorithm.
        assert!(CleanupMarker::parse(&format!("42:1234:SHA512:{hex}")).is_none());
        assert!(CleanupMarker::parse(&format!("42:1234:SHA256:{hex}:extra")).is_none());
    }

    #[test]
    fn cleanup_marker_scrubs_malformed_and_round_trips() {
        use crate::xattr_helpers::tests::assert_scrubs_malformed_and_round_trips;

        let marker = CleanupMarker::new(42, 1234, HashAlgo::Sha256, &[0xcdu8; 32]);
        assert_scrubs_malformed_and_round_trips(b"42:1234:SHA256:nothex", &marker);
    }
}
