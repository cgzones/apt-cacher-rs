use std::path::{Path, PathBuf};

use crate::fs_open::{
    hint_sequential_read, is_non_regular_errno, nofollow_nonblock_options, release_page_cache,
};
use crate::index_parser::{HashAlgo, hash_open_file};
use crate::metrics;
use crate::verified_marker::{has_valid_marker, stamp};

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
    /// The file is gone (removed since the scan listed it); nothing to
    /// verify, and not an I/O failure.
    Vanished,
    /// Open/read failed; cleanup leaves the file alone.
    IoError(std::io::Error),
}

/// Blocking digest-and-compare with an inode/size race check after hashing.
/// Runs on the blocking pool via [`verify_cache_file`].
fn verify_file_sync(path: &Path, algo: HashAlgo, expected: &[u8]) -> Verdict {
    use std::os::unix::fs::MetadataExt as _;

    let mut file = match nofollow_nonblock_options().read(true).open(path) {
        Ok(f) => f,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Verdict::Vanished,
        // A symlink swapped in since the scan: `O_NOFOLLOW` refuses it.
        Err(err) if is_non_regular_errno(&err) => {
            metrics::CACHE_NON_REGULAR.increment();
            return Verdict::NonRegular;
        }
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

    // Past the memo fast path, which reads nothing but one xattr: from here
    // the whole file is read, so the readahead hint is worth its syscall.
    hint_sequential_read(&file, pre_size, path);

    let computed = match algo {
        HashAlgo::Sha256 => hash_open_file::<sha2::Sha256>(&mut file),
        HashAlgo::Sha512 => hash_open_file::<sha2::Sha512>(&mut file),
    };
    let computed = match computed {
        Ok(hash) => hash,
        Err(err) => {
            metrics::CACHE_IO_FAILURE.increment();
            return Verdict::IoError(err);
        }
    };

    // The pages were read for a scheduled integrity pass, not for a client.
    // Without this a full cleanup streams the entire cache through the page
    // cache and evicts the hot serving set.
    release_page_cache(&file, path);

    if computed.as_slice() == expected {
        // Only stamp when the file is still the one we hashed — a swap
        // mid-hash must not mark the *new* content as verified.
        match std::fs::symlink_metadata(path) {
            Ok(post_meta) if post_meta.ino() == pre_ino && post_meta.len() == pre_size => {
                stamp(&file, path, pre_ino, pre_size, algo, expected);
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

/// Bound on concurrent whole-file hashes. Cleanup runs up to ten mirror
/// tasks, each of which would otherwise hash independently: ten concurrent
/// cold reads saturate the disk queue the serve path shares. Three keeps the
/// device busy without owning it.
const VERIFY_CONCURRENCY: usize = 3;

static VERIFY_SLOTS: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(VERIFY_CONCURRENCY);

pub(super) async fn verify_cache_file(path: PathBuf, algo: HashAlgo, expected: Vec<u8>) -> Verdict {
    let _permit = match VERIFY_SLOTS.acquire().await {
        Ok(permit) => permit,
        // `AcquireError` is a tuple struct with a private field, so the
        // usual explicit destructure is not available here. It can only be
        // returned by a closed semaphore, and this one is a private static
        // that nothing closes.
        Err(err) => return Verdict::IoError(std::io::Error::other(err)),
    };

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
        assert!(
            matches!(v, Verdict::Mismatch { .. }),
            "expected Mismatch verdict, got {v:?}"
        );
        let mismatch = if let Verdict::Mismatch { computed, size } = v {
            Some((computed, size))
        } else {
            None
        };
        let (computed, size) = mismatch.expect("asserted above");
        assert_eq!(computed, expected_sha256);
        assert_eq!(size, payload.len() as u64, "size is billed to the eviction");

        let expected_sha512 = sha2::Sha512::digest(payload).to_vec();
        assert!(matches!(
            verify_file_sync(&path, HashAlgo::Sha512, &expected_sha512),
            Verdict::Match
        ));
    }

    /// A file removed since the scan is a vanished entry: not an I/O
    /// failure, and counted nowhere.
    #[test]
    fn verify_file_sync_reports_a_missing_path_as_vanished() {
        let dir = tempfile::tempdir().expect("tempdir");
        let missing = dir.path().join("does_not_exist");
        let io_failure = metrics::CACHE_IO_FAILURE.get();
        assert!(matches!(
            verify_file_sync(&missing, HashAlgo::Sha256, &[0u8; 32]),
            Verdict::Vanished
        ));
        assert_eq!(metrics::CACHE_IO_FAILURE.get(), io_failure);
    }

    /// A symlink swapped in since the scan is refused by `O_NOFOLLOW`: a
    /// non-regular entry, not an I/O failure.
    #[test]
    fn verify_file_sync_reports_a_symlink_as_non_regular() {
        let dir = tempfile::tempdir().expect("tempdir");
        let target = dir.path().join("target");
        std::fs::write(&target, b"x").expect("write target");
        let link = dir.path().join("cache.deb");
        std::os::unix::fs::symlink(&target, &link).expect("symlink");

        let non_regular = metrics::CACHE_NON_REGULAR.get();
        let io_failure = metrics::CACHE_IO_FAILURE.get();
        let verdict = verify_file_sync(&link, HashAlgo::Sha256, &[0u8; 32]);
        assert!(matches!(verdict, Verdict::NonRegular), "{verdict:?}");
        assert_eq!(metrics::CACHE_NON_REGULAR.get(), non_regular + 1);
        assert_eq!(metrics::CACHE_IO_FAILURE.get(), io_failure);
    }

    #[test]
    fn verified_marker_memoizes_and_binds_expected_digest() {
        use std::io::Write as _;
        use std::os::unix::fs::MetadataExt as _;

        use crate::xattr_helpers::tests::supports_user_xattrs;
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

        if supports_user_xattrs(&path) {
            let file = std::fs::File::open(&path).expect("open");
            let meta = file.metadata().expect("metadata");
            assert!(has_valid_marker(
                &file,
                &path,
                meta.ino(),
                meta.len(),
                HashAlgo::Sha256,
                &expected,
            ));
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
}
