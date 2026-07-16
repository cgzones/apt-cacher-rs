use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use xattr::FileExt as _;

use crate::index_parser::{HashAlgo, hash_open_file, hex_encode};
use crate::metrics;
use crate::utils::nofollow_options;

/// Xattr recording a successful cleanup digest verification, formatted as
/// `"{ino}:{size}:{algo}:{expected-digest-hex}"`.
///
/// A later cycle skips re-hashing when inode, size, algorithm, and expected
/// digest all still match — the daily full-cache re-read otherwise scales
/// with total cache size instead of churn. Binding the expected digest
/// means an index update that changes the expected content invalidates the
/// marker automatically; binding `(ino, size)` means any re-download
/// (temp file + rename, so a fresh inode) invalidates it too.
const XATTR_CLEANUP_VERIFIED: &str = "user.apt_cacher_rs.cleanup_verified";

fn verified_marker(ino: u64, size: u64, algo: HashAlgo, expected: &[u8]) -> String {
    format!("{ino}:{size}:{}:{}", algo.as_str(), hex_encode(expected))
}

/// Whether `file` carries a verified marker matching the current identity
/// and expected digest. Any read failure or mismatch counts as "not
/// verified" (the caller re-hashes and re-stamps).
fn has_valid_marker(
    file: &std::fs::File,
    ino: u64,
    size: u64,
    algo: HashAlgo,
    expected: &[u8],
) -> bool {
    let Ok(Some(value)) = file.get_xattr(XATTR_CLEANUP_VERIFIED) else {
        return false;
    };
    value == verified_marker(ino, size, algo, expected).as_bytes()
}

/// Stamp the verified marker after a successful digest match. Best-effort:
/// failure (e.g. filesystem without xattr support) just means the next
/// cycle re-hashes.
fn stamp_marker(file: &std::fs::File, ino: u64, size: u64, algo: HashAlgo, expected: &[u8]) {
    let value = verified_marker(ino, size, algo, expected);
    if file
        .set_xattr(XATTR_CLEANUP_VERIFIED, value.as_bytes())
        .is_err()
    {
        // Same graceful degradation as xattr_helpers::write_helper; the
        // warn there is skipped here because cleanup would emit it once
        // per referenced file per cycle on xattr-less filesystems.
    }
}

/// Outcome of verifying a cache file against an expected digest.
#[derive(Debug)]
pub(super) enum Verdict {
    /// Computed digest equals the expected one.
    Match,
    /// Computed digest differs from the expected one and the underlying file
    /// did not change inode/size during hashing.
    Mismatch { computed: Vec<u8> },
    /// The file's `(inode, size)` changed between hash start and finish, so a
    /// concurrent writer raced us; the cleanup leaves the file alone.
    Raced,
    /// Open/read failed; cleanup leaves the file alone.
    IoError(std::io::Error),
}

/// Blocking digest-and-compare with an inode/size race check after hashing.
/// Runs on the blocking pool via [`verify_cache_file`].
pub(super) fn verify_file_sync(path: &Path, algo: HashAlgo, expected: &[u8]) -> Verdict {
    use std::os::unix::fs::MetadataExt as _;

    let mut file = match nofollow_options().read(true).open(path) {
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
            return Verdict::IoError(std::io::Error::new(
                ErrorKind::InvalidData,
                "Not a regular file",
            ));
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
    if has_valid_marker(&file, pre_ino, pre_size, algo, expected) {
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
                stamp_marker(&file, pre_ino, pre_size, algo, expected);
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
        Ok(_) => Verdict::Mismatch { computed },
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
        let Verdict::Mismatch { computed } = v else {
            unreachable!("expected Mismatch verdict, got {v:?}")
        };
        assert_eq!(computed, expected_sha256);

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
        let stamped = matches!(file.get_xattr(XATTR_CLEANUP_VERIFIED), Ok(Some(_)));
        if stamped {
            let before = metrics::CLEANUP_CHECKSUM_SKIPS.get();
            assert!(matches!(
                verify_file_sync(&path, HashAlgo::Sha256, &expected),
                Verdict::Match
            ));
            assert_eq!(
                metrics::CLEANUP_CHECKSUM_SKIPS.get(),
                before + 1,
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
}
