//! Cache-filesystem access primitives: symlink-refusing opens and stats,
//! and the per-file kernel hints (readahead, volatile mtime touch) that every
//! serve path applies.
//!
//! The `*nofollow*_options()` helpers are the clippy `disallowed-methods`
//! blessed construction sites for `OpenOptions`: every open of a path under
//! the cache directory goes through one of them so a symlink at the final
//! component is refused.

use std::path::Path;

use tracing::{error, warn};

use crate::{error::ErrorReport, log_once::Logged, metrics, warn_once_or_debug};

/// [`std::fs::OpenOptions`] with `O_NOFOLLOW` pre-set: every open of a path
/// under the cache directory must refuse a symlink at the final component.
/// Callers chain the remaining flags on the returned options.
///
/// `custom_flags` overwrites rather than ORs, so callers must NOT call
/// `.custom_flags()` again on the returned options.
pub(crate) fn nofollow_options() -> std::fs::OpenOptions {
    use std::os::unix::fs::OpenOptionsExt as _;

    #[expect(
        clippy::disallowed_methods,
        reason = "single blessed construction site"
    )]
    let mut options = std::fs::OpenOptions::new();
    options.custom_flags(nix::libc::O_NOFOLLOW);
    options
}

/// [`nofollow_options`] plus `O_NONBLOCK`, for opening a cache path that may
/// have been replaced by a non-regular file since it was last stat'd.
///
/// `open(O_RDONLY)` on a FIFO with no writer blocks indefinitely, which on a
/// blocking-pool thread strands that thread for the life of the process; the
/// same applies to some character devices. `O_NONBLOCK` is inert for regular
/// files, so the expected case is unaffected and the caller can reject anything
/// else after `fstat`. Use this instead of pre-stat'ing the path: an lstat only
/// narrows the race, it does not close it.
pub(crate) fn nofollow_nonblock_options() -> std::fs::OpenOptions {
    use std::os::unix::fs::OpenOptionsExt as _;

    #[expect(
        clippy::disallowed_methods,
        reason = "single blessed construction site"
    )]
    let mut options = std::fs::OpenOptions::new();
    options.custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK);
    options
}

/// [`nofollow_options`] over [`tokio::fs::OpenOptions`], with the same
/// `custom_flags` caveat.
pub(crate) fn tokio_nofollow_options() -> tokio::fs::OpenOptions {
    #[expect(
        clippy::disallowed_methods,
        reason = "single blessed construction site"
    )]
    let mut options = tokio::fs::OpenOptions::new();
    options.custom_flags(nix::libc::O_NOFOLLOW);
    options
}

/// Probe whether `path` is a real directory.
///
/// Uses `symlink_metadata` (lstat semantics) so a hostile symlink cannot
/// redirect a subsequent walk outside the cache tree.  On symlink / non-dir
/// the function logs a warning naming the operator-facing `purpose` (used to
/// build messages like *"Skipping {purpose} because root is a symlink: …"*),
/// and returns `Ok(false)` so the caller can treat the path as absent.
/// `NotFound` is reported as `Ok(false)` without logging — many callers
/// expect the path to be missing on fresh installs.
///
/// On any other I/O error, the error is returned untouched so the caller
/// can choose to log + propagate or log + swallow.
pub(crate) async fn probe_dir(path: &Path, purpose: &'static str) -> std::io::Result<bool> {
    match tokio::fs::symlink_metadata(path).await {
        Ok(md) if md.file_type().is_dir() => Ok(true),
        Ok(md) if md.file_type().is_symlink() => {
            warn!(
                "Skipping {purpose} because root is a symlink: `{}`",
                path.display()
            );
            Ok(false)
        }
        Ok(_) => {
            warn!(
                "Skipping {purpose} because root is not a directory: `{}`",
                path.display()
            );
            Ok(false)
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(err) => Err(err),
    }
}

/// Marker for a cache-file access that failed and was already logged, with
/// the matching `CACHE_IO_FAILURE` / `CACHE_NON_REGULAR` bump. Callers only
/// map it to their transport's 500 - never log it a second time; the carried
/// [`Logged`] is the proof.
#[derive(Debug)]
pub(crate) struct CacheAccessFailure(pub(crate) Logged);

/// `statx` an already-open file without the blocking-pool round trip.
///
/// Synchronous on purpose. `tokio::fs::File::metadata` is a `spawn_blocking`
/// under the hood — a condvar wake of a pool thread, a wake back to the
/// worker and two context switches for a stat of an in-memory inode, paid on
/// every cache hit. The late-joiner path in `sendfile_conn.rs` already stats
/// inline for the same reason.
///
/// It must stay a `statx`, not an `fstat`: `cache_file_http_date` reads
/// `Metadata::created()` (btime) and only falls back to mtime, while
/// [`touch_volatile_mtime`] repurposes mtime as "last revalidated". `fstat(2)`
/// carries no btime and nix 0.31 wraps no `statx`, so the fd is borrowed into
/// a `std::fs::File` and std's own `statx` is used.
fn borrowed_metadata(file: &tokio::fs::File) -> std::io::Result<std::fs::Metadata> {
    use std::mem::ManuallyDrop;
    use std::os::fd::{AsRawFd as _, FromRawFd as _};

    // SAFETY: `file` owns the descriptor and outlives this borrow, and
    // `ManuallyDrop` keeps the wrapper from closing it on drop, so the
    // borrowed `File` never takes ownership of the fd.
    let borrowed = ManuallyDrop::new(unsafe { std::fs::File::from_raw_fd(file.as_raw_fd()) });
    borrowed.metadata()
}

/// `statx` an open cache file and require a regular file.
///
/// The single owner of the "stat failed -> `CACHE_IO_FAILURE`, non-regular ->
/// `CACHE_NON_REGULAR`" policy for files about to be served: every serve path
/// (hyper, sendfile, splice) goes through here so no path can silently skip
/// the anomaly accounting.
pub(crate) fn regular_file_metadata(
    file: &tokio::fs::File,
    path: &Path,
) -> Result<std::fs::Metadata, CacheAccessFailure> {
    match borrowed_metadata(file) {
        Ok(md) if md.file_type().is_file() => Ok(md),
        Ok(_) => {
            metrics::CACHE_NON_REGULAR.increment();
            Err(CacheAccessFailure(Logged::error(format_args!(
                "Cache file `{}` is not a regular file; refusing to serve it",
                path.display()
            ))))
        }
        Err(err) => Err(CacheAccessFailure(Logged::cache_io_failure(format_args!(
            "Failed to get metadata of cache file `{}`; refusing to serve it:  {}",
            path.display(),
            ErrorReport(&err)
        )))),
    }
}

/// Update a volatile file's mtime to `now` to reset the 30-second freshness window.
/// Only updates mtime when the filesystem supports birth time (btime), so mtime can
/// serve as a "last revalidated" timestamp separate from the content creation time.
/// Takes ownership of the file handle (for the `into_std()` / `from_std()` conversion
/// needed by `set_modified()`) and returns it for continued use.
pub(crate) async fn touch_volatile_mtime(
    file: tokio::fs::File,
    display_path: &Path,
) -> tokio::fs::File {
    let mdata = match borrowed_metadata(&file) {
        Ok(m) => m,
        Err(err) => {
            metrics::CACHE_IO_FAILURE.increment();
            error!(
                "Failed to get metadata of cached file `{}`; leaving its volatile freshness window untouched:  {}",
                display_path.display(),
                ErrorReport(&err)
            );
            return file;
        }
    };
    // Cache entries are replaced on update, not overwritten, so the creation time (btime)
    // represents the actual content age.  Mtime is repurposed as a "last revalidated"
    // timestamp.  If the filesystem does not support btime, updating mtime would destroy
    // the only content-age signal, so skip the update in that case.
    if mdata.created().is_err() {
        return file;
    }

    // Refactor when https://github.com/tokio-rs/tokio/issues/6368 is resolved
    let std_file = file.into_std().await;
    let now = std::time::SystemTime::now();
    let result = tokio::task::block_in_place(|| std_file.set_modified(now));
    if let Err(err) = result {
        error!(
            "Failed to update the modification time of `{}`; its volatile freshness window is not reset:  {}",
            display_path.display(),
            ErrorReport(&err)
        );
    }
    tokio::fs::File::from_std(std_file)
}

/// Transfers below this size don't get a readahead hint: the kernel's
/// default readahead window (128 KiB) already covers them, so the
/// `posix_fadvise` syscall would be pure per-request overhead — hot small
/// index files are the dominant request class.
const SEQUENTIAL_HINT_MIN_SIZE: u64 = 256 * 1024;

/// Hint to the kernel that `file` will be read sequentially from start to end,
/// so the page-cache readahead window can grow more aggressively.  Used on
/// every cache file we are about to stream to a client through the
/// hyper/sendfile paths, and on files hashed for integrity verification.
/// Accepts any `AsFd`, so both `tokio::fs::File` (async serve paths) and
/// `std::fs::File` (synchronous hashing) can call it.  `transfer_size` is the
/// number of bytes about to be read (`u64::MAX` when unknown, e.g. a
/// still-growing download); small transfers skip the syscall.  Failure is
/// non-fatal — the first failure is logged at warn level (subsequent ones at
/// debug) and we fall back to the kernel's default readahead policy.
pub(crate) fn hint_sequential_read(
    file: impl std::os::fd::AsFd,
    transfer_size: u64,
    display_path: &Path,
) {
    use nix::fcntl::{PosixFadviseAdvice, posix_fadvise};

    if transfer_size < SEQUENTIAL_HINT_MIN_SIZE {
        return;
    }

    // Avoid using `tokio::task::block_in_place`, since no real I/O is involved.
    // SEQUENTIAL only (not NOREUSE): a cache proxy wants the pages retained for
    // reuse across clients, which NOREUSE would drop after this read.
    if let Err(errno) = posix_fadvise(file, 0, 0, PosixFadviseAdvice::POSIX_FADV_SEQUENTIAL) {
        warn_once_or_debug!(
            "Failed to hint sequential reads via posix_fadvise(2) for `{}`; falling back to the kernel's default readahead:  {}",
            display_path.display(),
            ErrorReport(&errno)
        );
    }
}

/// Tell the kernel the pages of `file` are no longer needed, after a full
/// read that was not on behalf of a client.
///
/// Cleanup hashes its way through the whole cache on a schedule; without
/// this, one pass streams every file through the page cache and evicts the
/// hot serving set. Deliberately NOT used at commit time, where the file was
/// just written and may be served within milliseconds. Failure is non-fatal
/// — the first is logged at warn level, subsequent ones at debug.
pub(crate) fn release_page_cache(file: impl std::os::fd::AsFd, display_path: &Path) {
    use nix::fcntl::{PosixFadviseAdvice, posix_fadvise};

    // Offset 0, length 0: the whole file, per posix_fadvise(2).
    if let Err(errno) = posix_fadvise(file, 0, 0, PosixFadviseAdvice::POSIX_FADV_DONTNEED) {
        warn_once_or_debug!(
            "Failed to release the page cache via posix_fadvise(2) for `{}`; the cleanup pass keeps its pages resident:  {}",
            display_path.display(),
            ErrorReport(&errno)
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Create `dir/target` and a `dir/link` symlink pointing at it.
    fn planted_symlink(dir: &Path) -> std::path::PathBuf {
        let target = dir.join("target");
        std::fs::write(&target, b"x").expect("write target");
        let link = dir.join("link");
        std::os::unix::fs::symlink(&target, &link).expect("symlink");
        link
    }

    #[test]
    fn nofollow_options_refuse_a_symlink_with_eloop() {
        let dir = tempfile::tempdir().expect("tempdir");
        let link = planted_symlink(dir.path());

        for mut options in [nofollow_options(), nofollow_nonblock_options()] {
            let err = options
                .read(true)
                .open(&link)
                .expect_err("O_NOFOLLOW must refuse a symlink at the final component");
            // `ErrorKind::FilesystemLoop` is nightly-only, so every caller
            // matching a refused symlink compares the raw errno instead.
            assert_eq!(
                err.raw_os_error(),
                Some(nix::libc::ELOOP),
                "a refused symlink is recognized by ELOOP"
            );
        }
    }

    #[tokio::test]
    async fn tokio_nofollow_options_refuses_a_symlink_with_eloop() {
        let dir = tempfile::tempdir().expect("tempdir");
        let link = planted_symlink(dir.path());

        let err = tokio_nofollow_options()
            .read(true)
            .open(&link)
            .await
            .expect_err("O_NOFOLLOW must refuse a symlink at the final component");
        assert_eq!(
            err.raw_os_error(),
            Some(nix::libc::ELOOP),
            "a refused symlink is recognized by ELOOP"
        );
    }

    /// The nonblock variant exists so an open of a FIFO or character device
    /// cannot strand a blocking-pool thread; `custom_flags` overwrites rather
    /// than ORs, so a stray second call would silently drop `O_NONBLOCK`.
    #[test]
    fn only_the_nonblock_variant_sets_o_nonblock() {
        use nix::fcntl::{FcntlArg, OFlag, fcntl};
        use std::os::fd::AsFd as _;

        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("regular");
        std::fs::write(&path, b"x").expect("write");

        let flags_of = |file: &std::fs::File| {
            OFlag::from_bits_truncate(fcntl(file.as_fd(), FcntlArg::F_GETFL).expect("F_GETFL"))
        };

        let nonblock = nofollow_nonblock_options()
            .read(true)
            .open(&path)
            .expect("open");
        assert!(
            flags_of(&nonblock).contains(OFlag::O_NONBLOCK),
            "the nonblock variant must keep O_NONBLOCK, got {:?}",
            flags_of(&nonblock)
        );

        let plain = nofollow_options().read(true).open(&path).expect("open");
        assert!(
            !flags_of(&plain).contains(OFlag::O_NONBLOCK),
            "the plain variant sets only O_NOFOLLOW, got {:?}",
            flags_of(&plain)
        );
    }

    #[tokio::test]
    async fn regular_file_metadata_reports_size_without_blocking_pool() {
        use std::io::Write as _;

        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("cached.deb");
        {
            let mut f = std::fs::File::create(&path).expect("create");
            f.write_all(b"0123456789").expect("write");
        }
        let file = tokio::fs::File::open(&path).await.expect("open");

        let meta = regular_file_metadata(&file, &path).expect("regular file");

        assert_eq!(meta.len(), 10);
        // `regular_file_metadata` must stay statx-backed: compare its
        // `created()` availability against a path-based std stat (which
        // goes through the same statx). This fails if the helper ever
        // regresses to an fstat(2), which carries no btime, while staying
        // green on a filesystem that genuinely reports none -- an `||`
        // against `modified()` would not, since `modified()` is `Ok`
        // whenever the stat itself succeeds.
        let via_path = std::fs::metadata(&path).expect("path stat");
        assert_eq!(
            meta.created().is_ok(),
            via_path.created().is_ok(),
            "regular_file_metadata must stay statx-backed; an fstat(2) loses btime"
        );
    }

    #[tokio::test]
    async fn regular_file_metadata_rejects_a_directory() {
        let dir = tempfile::tempdir().expect("tempdir");
        let file = tokio::fs::File::open(dir.path()).await.expect("open dir");

        assert!(
            regular_file_metadata(&file, dir.path()).is_err(),
            "a directory is not a regular file and must be refused"
        );
    }
}
