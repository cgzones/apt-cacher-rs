use std::io::ErrorKind;
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};

use crate::index_parser::{HashAlgo, hash_open_file};
use crate::metrics;

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

    let mut file = match std::fs::File::options()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW)
        .open(path)
    {
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
}
