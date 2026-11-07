use std::path::{Path, PathBuf};

use crate::fs_open::{
    hint_sequential_read, is_non_regular_errno, nofollow_nonblock_options, release_page_cache,
};
use crate::index_parser::{Digest, hash_open_file};
use crate::metrics;
use crate::verified_marker::{FileIdentity, has_valid_marker, stamp};

/// Outcome of verifying a cache file against an expected digest.
#[derive(Debug)]
pub(super) enum Verdict {
    /// Computed digest equals the expected one.
    Match,
    /// Computed digest differs from the expected one and the underlying file
    /// kept its [`FileIdentity`] during hashing. `size` is the on-disk size
    /// observed before hashing, which the caller bills to the eviction.
    Mismatch { computed: Digest, size: u64 },
    /// The file's [`FileIdentity`] (inode, size, mtime) changed between hash
    /// start and finish, so a concurrent writer raced us; the cleanup leaves
    /// the file alone.
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

/// What [`open_and_check_marker`] found: a verdict reached without reading
/// the file, or the open file still to be hashed.
enum Opened {
    Decided(Verdict),
    NeedsHash {
        file: std::fs::File,
        pre_identity: FileIdentity,
        pre_size: u64,
    },
}

/// Blocking digest-and-compare with a [`FileIdentity`] race check after
/// hashing: [`open_and_check_marker`] then [`hash_and_compare`], the two
/// steps [`verify_cache_file`] runs as separate blocking jobs.
#[cfg(test)]
fn verify_file_sync(path: &Path, expected: &Digest) -> Verdict {
    match open_and_check_marker(path, expected) {
        Opened::Decided(verdict) => verdict,
        Opened::NeedsHash {
            file,
            pre_identity,
            pre_size,
        } => hash_and_compare(file, path, pre_identity, pre_size, expected),
    }
}

/// Open the cache file and take the memoized fast path if its marker still
/// vouches for it. Blocking, but reads nothing of the file's contents: one
/// open, one fstat and one xattr read.
fn open_and_check_marker(path: &Path, expected: &Digest) -> Opened {
    let file = match nofollow_nonblock_options().read(true).open(path) {
        Ok(f) => f,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return Opened::Decided(Verdict::Vanished);
        }
        // A symlink swapped in since the scan: `O_NOFOLLOW` refuses it.
        Err(err) if is_non_regular_errno(&err) => {
            metrics::CACHE_NON_REGULAR.increment();
            return Opened::Decided(Verdict::NonRegular);
        }
        Err(err) => {
            metrics::CACHE_IO_FAILURE.increment();
            return Opened::Decided(Verdict::IoError(err));
        }
    };
    let pre_meta = match file.metadata() {
        Ok(m) if m.file_type().is_file() => m,
        Ok(_) => {
            metrics::CACHE_NON_REGULAR.increment();
            return Opened::Decided(Verdict::NonRegular);
        }
        Err(err) => {
            metrics::CACHE_IO_FAILURE.increment();
            return Opened::Decided(Verdict::IoError(err));
        }
    };
    let pre_identity = FileIdentity::of(&pre_meta);

    // Memoized fast path: verified in an earlier cycle and unchanged since
    // (same inode/size/mtime, same expected digest) — skip the full
    // read+hash.
    if has_valid_marker(&file, path, pre_identity, expected) {
        metrics::CLEANUP_CHECKSUM_SKIPS.increment();
        return Opened::Decided(Verdict::Match);
    }

    Opened::NeedsHash {
        file,
        pre_identity,
        pre_size: pre_meta.len(),
    }
}

/// Hash the file [`open_and_check_marker`] opened and compare the digest,
/// checking afterwards that `path` still names the file hashed (by
/// `pre_identity`). Blocking: reads the whole file.
fn hash_and_compare(
    mut file: std::fs::File,
    path: &Path,
    pre_identity: FileIdentity,
    pre_size: u64,
    expected: &Digest,
) -> Verdict {
    // Past the memo fast path, which reads nothing but one xattr: from here
    // the whole file is read, so the readahead hint is worth its syscall.
    hint_sequential_read(&file, pre_size, path);

    let computed = match hash_open_file(expected.algo(), &mut file, pre_size) {
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

    if &computed == expected {
        // Only stamp when the file is still the one we hashed — a swap or
        // an in-place rewrite mid-hash must not mark the *new* content as
        // verified.
        match std::fs::symlink_metadata(path) {
            Ok(post_meta) if FileIdentity::of(&post_meta) == pre_identity => {
                stamp(&file, path, pre_identity, expected);
            }
            Ok(_) | Err(_) => {}
        }
        return Verdict::Match;
    }

    // Race check: a fresh download finishing mid-hash replaces the file via
    // rename (different inode), and an in-place rewrite moves its size or
    // mtime. Either way our digest is for content no longer at `path`, so
    // bail. Use `symlink_metadata` (lstat): a hostile symlink planted at
    // `path` after the open could otherwise point at a file whose identity
    // happens to match `pre_identity`, masking the race.  lstat compares the
    // symlink itself, so a swap is always detected.
    //
    // A stat failure here (e.g. another cleanup task already unlinked the
    // file, or EACCES) is treated like the pre-hash stat failure: bump and
    // return `Verdict::IoError` so the caller logs and retains.  Falling
    // through to `Verdict::Mismatch` would emit a false checksum-corruption
    // warn and then attempt a doomed `remove_file` on the missing path.
    match std::fs::symlink_metadata(path) {
        Ok(post_meta) if FileIdentity::of(&post_meta) != pre_identity => Verdict::Raced,
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

/// Verify the cache file at `path` against `expected`.
///
/// Two blocking jobs: the open and the memoized-marker check
/// ([`open_and_check_marker`]) run unthrottled -- in steady state they
/// answer nearly every file -- and only a file that must really be hashed
/// takes one of the [`VERIFY_SLOTS`], so a few cold multi-second hashes
/// never stall other mirrors' microsecond marker checks behind them. The
/// hash job keeps the descriptor the first job opened, so its type and
/// identity checks still hold for the file it reads.
pub(super) async fn verify_cache_file(path: PathBuf, expected: Digest) -> Verdict {
    let (opened, path, expected) = match tokio::task::spawn_blocking(move || {
        let opened = open_and_check_marker(&path, &expected);
        (opened, path, expected)
    })
    .await
    {
        Ok(checked) => checked,
        Err(join_err) => return Verdict::IoError(std::io::Error::other(join_err)),
    };
    let (file, pre_identity, pre_size) = match opened {
        Opened::Decided(verdict) => return verdict,
        Opened::NeedsHash {
            file,
            pre_identity,
            pre_size,
        } => (file, pre_identity, pre_size),
    };

    let permit = match VERIFY_SLOTS.acquire().await {
        Ok(permit) => permit,
        // `AcquireError` is a tuple struct with a private field, so the
        // usual explicit destructure is not available here. It can only be
        // returned by a closed semaphore, and this one is a private static
        // that nothing closes.
        Err(err) => return Verdict::IoError(std::io::Error::other(err)),
    };

    // The permit moves into the blocking job, which runs on even if this
    // future is dropped mid-hash: held here, a cancellation would free the
    // slot early and let one more hash run than `VERIFY_CONCURRENCY` allows.
    // Nothing cancels it today (each mirror's cleanup is a spawned task that
    // awaits its hashes inline); this keeps the bound from resting on that.
    match tokio::task::spawn_blocking(move || {
        let _permit = permit;
        hash_and_compare(file, &path, pre_identity, pre_size, &expected)
    })
    .await
    {
        Ok(v) => v,
        Err(join_err) => Verdict::IoError(std::io::Error::other(join_err)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::index_parser::HashAlgo;

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
            verify_file_sync(
                &path,
                &Digest::from_bytes(HashAlgo::Sha256, &expected_sha256)
                    .expect("matching digest length")
            ),
            Verdict::Match
        ));

        let wrong: Vec<u8> = vec![0u8; 32];
        let v = verify_file_sync(
            &path,
            &Digest::from_bytes(HashAlgo::Sha256, &wrong).expect("matching digest length"),
        );
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
        assert_eq!(computed.as_slice(), expected_sha256);
        assert_eq!(size, payload.len() as u64, "size is billed to the eviction");

        let expected_sha512 = sha2::Sha512::digest(payload).to_vec();
        assert!(matches!(
            verify_file_sync(
                &path,
                &Digest::from_bytes(HashAlgo::Sha512, &expected_sha512)
                    .expect("matching digest length")
            ),
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
            verify_file_sync(
                &missing,
                &Digest::from_bytes(HashAlgo::Sha256, &[0u8; 32]).expect("matching digest length")
            ),
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
        let verdict = verify_file_sync(
            &link,
            &Digest::from_bytes(HashAlgo::Sha256, &[0u8; 32]).expect("matching digest length"),
        );
        assert!(matches!(verdict, Verdict::NonRegular), "{verdict:?}");
        assert_eq!(metrics::CACHE_NON_REGULAR.get(), non_regular + 1);
        assert_eq!(metrics::CACHE_IO_FAILURE.get(), io_failure);
    }

    #[test]
    fn verified_marker_memoizes_and_binds_expected_digest() {
        use std::io::Write as _;

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
            verify_file_sync(
                &path,
                &Digest::from_bytes(HashAlgo::Sha256, &expected).expect("matching digest length")
            ),
            Verdict::Match
        ));

        if supports_user_xattrs(&path) {
            let file = std::fs::File::open(&path).expect("open");
            let meta = file.metadata().expect("metadata");
            assert!(has_valid_marker(
                &file,
                &path,
                FileIdentity::of(&meta),
                &Digest::from_bytes(HashAlgo::Sha256, &expected).expect("matching digest length")
            ));
            // The counter is process-global and other unit tests in this
            // binary bump it concurrently, so assert the delta as a lower
            // bound.
            let before = metrics::CLEANUP_CHECKSUM_SKIPS.get();
            assert!(matches!(
                verify_file_sync(
                    &path,
                    &Digest::from_bytes(HashAlgo::Sha256, &expected)
                        .expect("matching digest length")
                ),
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
            verify_file_sync(
                &path,
                &Digest::from_bytes(HashAlgo::Sha256, &wrong).expect("matching digest length")
            ),
            Verdict::Mismatch { .. }
        ));
    }

    /// A verified file rewritten in place with different bytes of the same
    /// length keeps its inode and size; the mtime it gains must void the
    /// marker, so the next cycle re-hashes it and finds the mismatch.
    #[test]
    fn verified_marker_does_not_cover_a_same_size_rewrite_in_place() {
        use std::io::{Seek as _, Write as _};
        use std::os::unix::fs::MetadataExt as _;

        use crate::fs_open::nofollow_options;
        use crate::xattr_helpers::tests::supports_user_xattrs;
        use sha2::Digest as _;

        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("cache.deb");
        let payload = b"original package payload";
        std::fs::write(&path, payload).expect("write");
        if !supports_user_xattrs(&path) {
            return;
        }
        let expected = sha2::Sha256::digest(payload).to_vec();
        assert!(matches!(
            verify_file_sync(
                &path,
                &Digest::from_bytes(HashAlgo::Sha256, &expected).expect("matching digest length")
            ),
            Verdict::Match
        ));
        let stamped = std::fs::metadata(&path).expect("stat");
        {
            let file = std::fs::File::open(&path).expect("open");
            assert!(
                has_valid_marker(
                    &file,
                    &path,
                    FileIdentity::of(&stamped),
                    &Digest::from_bytes(HashAlgo::Sha256, &expected)
                        .expect("matching digest length")
                ),
                "the first verification must stamp the marker"
            );
        }

        // Rewrite in place: same inode, same length, different bytes. Pin a
        // later mtime explicitly so a coarse timestamp tick cannot hide it.
        {
            let mut file = nofollow_options()
                .write(true)
                .open(&path)
                .expect("open for rewrite");
            file.rewind().expect("rewind");
            file.write_all(&payload.map(|_| b'X')).expect("rewrite");
        }
        filetime::set_file_mtime(
            &path,
            filetime::FileTime::from_unix_time(stamped.mtime() + 60, 0),
        )
        .expect("set mtime");
        let rewritten = std::fs::metadata(&path).expect("stat");
        assert_eq!(rewritten.ino(), stamped.ino(), "rewritten in place");
        assert_eq!(rewritten.len(), stamped.len(), "same length");

        let verdict = verify_file_sync(
            &path,
            &Digest::from_bytes(HashAlgo::Sha256, &expected).expect("matching digest length"),
        );
        assert!(
            matches!(verdict, Verdict::Mismatch { .. }),
            "the stale marker must not vouch for rewritten content, got {verdict:?}"
        );
    }
}
