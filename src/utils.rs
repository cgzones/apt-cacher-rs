use std::{
    ops::Deref,
    path::{Path, PathBuf},
};

use log::{debug, error, info, warn};
use rand::{RngExt as _, distr::Alphanumeric, rngs::SmallRng};

use crate::{
    Never,
    cache_layout::{SUBDIR_FLAT, SUBDIR_TMP},
    deb_mirror, global_config,
    guards::InitBarrier,
    http_etag::read_etag,
    http_range::HttpDate,
    humanfmt::HumanFmt,
    metrics, warn_once_or_debug, xattr_helpers,
};

/// Compile-time macro for creating a `NonZero` value, panicking if the value is zero.
#[macro_export]
macro_rules! nonzero {
    ($exp:expr) => {
        const {
            match ::std::num::NonZero::new($exp) {
                Some(v) => v,
                None => panic!("nonzero!() called with zero value"),
            }
        }
    };
}

/// Compile-time assertion macro.
#[macro_export]
macro_rules! static_assert {
    ($cond:expr) => {
        const _: () = assert!($cond);
    };
    ($cond:expr, $msg:expr) => {
        const _: () = assert!($cond, $msg);
    };
}

/// Returns `true` when `err` indicates the peer terminated the connection
/// (by reset, abort, half-close, EOF, or socket-level timeout). Used to
/// demote routine "client went away" log lines from warn to info, since
/// they are not actionable for the operator.
#[must_use]
pub(crate) fn is_peer_disconnect(err: &std::io::Error) -> bool {
    use std::io::ErrorKind;
    matches!(
        err.kind(),
        ErrorKind::BrokenPipe
            | ErrorKind::ConnectionAborted
            | ErrorKind::ConnectionReset
            | ErrorKind::NotConnected
            | ErrorKind::TimedOut
            | ErrorKind::UnexpectedEof
    )
}

/// Walks the `Error::source()` chain looking for any `std::io::Error` with
/// `ErrorKind::TimedOut`. Used to attribute `hyper-timeout` firings on the
/// connector's connect/read/write paths to the matching upstream timeout
/// counter; classifies any wrapped `TimedOut` io error regardless of which
/// phase produced it.
#[must_use]
pub(crate) fn is_io_timed_out_in_chain(err: &(dyn std::error::Error + 'static)) -> bool {
    let mut cur: Option<&(dyn std::error::Error + 'static)> = Some(err);
    while let Some(e) = cur {
        if let Some(io) = e.downcast_ref::<std::io::Error>()
            && io.kind() == std::io::ErrorKind::TimedOut
        {
            return true;
        }
        cur = e.source();
    }
    false
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

/// Tri-state of an in-progress download's partial-file handling.
///
/// - `Volatile`: non-permanent cache flavor — no partial-file semantics; caller creates a
///   random temp file for the download.
/// - `Fresh`: permanent cache flavor with no valid existing partial; the guard reserves
///   the deterministic partial path so a failed download can be resumed on the next attempt.
/// - `Resumable`: permanent cache flavor with an existing valid partial whose file handle
///   has been held open since the size/ETag check (avoiding TOCTOU); caller resumes from
///   `file`'s current offset.
pub(crate) enum PartialDownload {
    Volatile,
    Fresh(TempPath),
    Resumable {
        file: tokio::fs::File,
        guard: TempPath,
    },
}

impl PartialDownload {
    /// Downgrade a `Resumable` state to `Fresh` by removing the stale partial file and
    /// re-creating the guard for the same path.  No-op for `Fresh` and `Volatile`.
    pub(crate) async fn discard_resume(&mut self) {
        *self = match std::mem::replace(self, Self::Volatile) {
            Self::Volatile => Self::Volatile,
            Self::Fresh(guard) => Self::Fresh(guard),
            Self::Resumable { file, guard } => {
                drop(file);
                Self::Fresh(guard.renew().await)
            }
        };
    }
}

/// Outcome of [`prepare_partial_resume`]: byte offset, expected total size
/// from xattr, `If-Range` validator, and the file-handle/path state to thread
/// into the download body.
pub(crate) struct PartialResume {
    pub(crate) offset: u64,
    pub(crate) expected_total: Option<u64>,
    pub(crate) if_range: Option<String>,
    pub(crate) partial: PartialDownload,
}

impl PartialResume {
    fn fresh(guard: TempPath) -> Self {
        Self {
            offset: 0,
            expected_total: None,
            if_range: None,
            partial: PartialDownload::Fresh(guard),
        }
    }
}

/// Open any existing partial download for `ibarrier`'s target and decide
/// whether it can be safely resumed.
///
/// Strong-validator requirement: a partial is only resumable when it carries
/// a stored upstream `ETag`.  RFC 9110 §8.8.2.2 requires a strong validator
/// for `If-Range`; `Last-Modified` / mtime are weak when the origin does not
/// guarantee sub-second-unique change detection — Debian mirror infrastructure
/// does not — and the stored total-size xattr is insufficient to detect a
/// same-size replacement within the mtime granularity.  Partials without an
/// `ETag` are therefore discarded rather than risk silent concatenation of
/// bytes from two different upstream revisions.
///
/// `log_prefix` is prepended to every emitted log line (e.g. `""` for the
/// hyper path, `"splice proxy: "` for the splice path).
///
/// Returns `Ok` for both the resumable and fresh outcomes; the caller
/// distinguishes via `partial`/`offset`.  Returns `Err((io_err, guard))` only
/// when the open syscall failed with a kind other than `NotFound` — callers
/// decide whether to bail or fall through to a fresh download (the partial
/// path is left untouched on the filesystem either way).
pub(crate) async fn prepare_partial_resume(
    ibarrier: &InitBarrier<'_>,
    debname: &str,
    mirror: &deb_mirror::Mirror,
    log_prefix: &'static str,
) -> Result<PartialResume, (std::io::Error, TempPath)> {
    match open_partial_file(ibarrier, log_prefix).await {
        Ok((file, size, _mtime, guard)) if size > 0 => {
            if let Some(if_range) = read_etag(&file, &guard) {
                let expected_total = xattr_helpers::read_expected_size(&file, &guard);
                info!(
                    "{log_prefix}found partial download ({} out of {}) for {debname} from mirror {mirror}, will attempt resume",
                    HumanFmt::Size(size),
                    expected_total
                        .map_or_else(|| "??".to_string(), |s| HumanFmt::Size(s).to_string()),
                );
                Ok(PartialResume {
                    offset: size,
                    expected_total,
                    if_range: Some(if_range),
                    partial: PartialDownload::Resumable { file, guard },
                })
            } else {
                warn!(
                    "{log_prefix}partial download for {debname} from mirror {mirror} lacks a strong upstream ETag, discarding instead of resuming",
                );
                drop(file);
                Ok(PartialResume::fresh(guard.renew().await))
            }
        }
        Ok((_file, _size, _mtime, guard)) => Ok(PartialResume::fresh(guard)),
        Err((err, guard)) => Err((err, guard)),
    }
}

/// A temporary file-path guard that automatically deletes the underlying file when dropped.
///
/// When `keep_on_drop` is set to `true`, the file is preserved on drop instead of being deleted.
/// This is used for partial download files that should survive failures for later resumption.
pub(crate) struct TempPath {
    path: Option<PathBuf>,
    keep_on_drop: bool,
}

impl TempPath {
    /// Defuse the temporary path guard, returning the underlying `PathBuf`.
    pub(crate) fn defuse(mut self) -> PathBuf {
        std::mem::take(&mut self.path).expect("path has not been destructed yet")
    }

    /// Force deletion of the underlying file regardless of `keep_on_drop`.
    async fn remove(mut self) -> PathBuf {
        let path = std::mem::take(&mut self.path).expect("path has not been destructed yet");

        if let Err(err) = tokio::fs::remove_file(&path).await {
            let level = if err.kind() == std::io::ErrorKind::NotFound {
                log::Level::Warn
            } else {
                log::Level::Error
            };
            log::log!(
                level,
                "Failed to remove partial file `{}`:  {err}",
                path.display()
            );
        }

        path
    }

    /// Remove the underlying file and return a fresh `TempPath` guarding the same path
    /// with `keep_on_drop = true` so a retried download can still be resumed on failure.
    async fn renew(self) -> Self {
        Self {
            path: Some(self.remove().await),
            keep_on_drop: true,
        }
    }
}

impl Drop for TempPath {
    fn drop(&mut self) {
        if let Some(path) = self.path.take() {
            if self.keep_on_drop {
                debug!(
                    "Keeping partial download file `{}` for future resumption",
                    path.display()
                );
                return;
            }
            tokio::task::spawn_blocking(move || {
                if let Err(err) = std::fs::remove_file(&path) {
                    error!(
                        "Failed to remove temporary file `{}`:  {err}",
                        path.display()
                    );
                } else {
                    debug!("Removed temporary file `{}`", path.display());
                }
            });
        }
    }
}

impl Deref for TempPath {
    type Target = Path;

    fn deref(&self) -> &Self::Target {
        self.path
            .as_deref()
            .expect("path has not been destructed yet")
    }
}

impl AsRef<Path> for TempPath {
    fn as_ref(&self) -> &Path {
        self.path
            .as_deref()
            .expect("path has not been destructed yet")
    }
}

/// Create a temporary file with a unique extension for the given path.
pub(crate) async fn tokio_tempfile(
    path: &Path,
    mode: u32,
) -> Result<(tokio::fs::File, TempPath), tokio::io::Error> {
    let mut rng: SmallRng = rand::make_rng();

    let mut buf = path.to_path_buf();

    let mut tries = 0;
    loop {
        const MAX_TRIES: u32 = 10;

        let s: String = (&mut rng)
            .sample_iter(Alphanumeric)
            .take(6)
            .map(char::from)
            .collect();

        assert!(
            buf.set_extension(s),
            "buf is non-empty so adding a new extension must succeed"
        );

        let _: Never = match tokio::fs::File::options()
            .create_new(true)
            .write(true)
            .mode(mode)
            .open(&buf)
            .await
        {
            Ok(file) => {
                return Ok((
                    file,
                    TempPath {
                        path: Some(buf),
                        keep_on_drop: false,
                    },
                ));
            }
            Err(err) if err.kind() == tokio::io::ErrorKind::AlreadyExists => {
                tries += 1;
                if tries > MAX_TRIES {
                    return Err(err);
                }
                assert!(
                    buf.set_extension(""),
                    "buf is non-empty so removing an existing extension must succeed"
                );
                continue;
            }
            Err(err) => return Err(err),
        };
    }
}

/// Build the deterministic on-disk path for a download's `.partial` temp
/// file.  The tmp file lives as a *sibling* of the eventual rename target,
/// so the atomic `rename(2)` after the download finishes stays within the
/// same filesystem.
///
/// Layout (parallels [`crate::cache_layout::ConnectionDetails::cache_dir_path`]):
///
/// - Structured: `{cache_directory}/{host}/{mirror_path}/tmp/{debname}.partial`
/// - Flat:        `{cache_directory}/{host}/flat/{mirror_path}/tmp/{debname}.partial`
///
/// `{host}` is the alias-resolved host when the request was redirected
/// (mirroring [`ConnectionDetails::cache_dir_path`]); otherwise it is the
/// mirror's own host.  Using the same host on both sides keeps the
/// `.partial` co-located with its rename target so the sibling guarantee
/// holds.
///
/// Disambiguation between flat-pool `.deb`s sharing a basename across
/// different sub-directories (`apt/amd64/foo.deb` vs `apt/arm64/foo.deb`)
/// is implicit in [`crate::deb_mirror::Mirror::path`], which equals the
/// URL-dir verbatim under the host-anchored flat layout.
fn partial_path_for_barrier(ibarrier: &InitBarrier<'_>) -> PathBuf {
    let mirror = ibarrier.mirror();
    let layout = ibarrier.layout();
    let host = ibarrier.aliased_host().unwrap_or_else(|| mirror.host());
    let filename = format!("{debname}.partial", debname = ibarrier.debname());
    let filename_path = Path::new(&filename);
    assert!(
        filename_path.is_relative(),
        "path construction must not contain absolute components"
    );

    if layout.is_flat() {
        let host_dir = host.format_cache_dir(mirror.port());
        let host_path = Path::new(&*host_dir);
        assert!(
            host_path.is_relative(),
            "path construction must not contain absolute components"
        );
        let mirror_path_relative = Path::new(mirror.path());
        assert!(
            mirror_path_relative.is_relative(),
            "path construction must not contain absolute components"
        );
        [
            &global_config().cache_directory,
            host_path,
            Path::new(SUBDIR_FLAT),
            mirror_path_relative,
            Path::new(SUBDIR_TMP),
            filename_path,
        ]
        .iter()
        .collect()
    } else {
        let mirror_dir = deb_mirror::mirror_cache_path_impl(host, mirror.port(), mirror.path());
        [
            &global_config().cache_directory,
            mirror_dir.as_path(),
            Path::new(SUBDIR_TMP),
            filename_path,
        ]
        .iter()
        .collect()
    }
}

/// Open an existing partial file for writing at the end, returning the file, its current size,
/// the file's modification time, and a `TempPath` guard with `keep_on_drop: true`.
///
/// Uses `write(true)` + seek instead of `append(true)` so that splice(2) can use explicit
/// file offsets (`O_APPEND` is incompatible with splice's offset parameter).
///
/// By opening the file and querying size + mtime from the same file handle, this avoids
/// TOCTOU races between a separate `metadata()` check and a later `open()`.
async fn open_partial_file(
    ibarrier: &InitBarrier<'_>,
    log_prefix: &'static str,
) -> Result<(tokio::fs::File, u64, HttpDate, TempPath), (tokio::io::Error, TempPath)> {
    use tokio::io::AsyncSeekExt as _;

    async fn file_ops(
        path: &Path,
        log_prefix: &'static str,
    ) -> Result<(tokio::fs::File, u64, HttpDate), tokio::io::Error> {
        let mut file = tokio::fs::File::options()
            .write(true)
            .read(true)
            .custom_flags(nix::libc::O_NOFOLLOW)
            .open(path)
            .await
            .inspect_err(|err| {
                // NotFound is the normal "no partial file" case; the caller
                // turns it into a fresh download.  Don't pollute the failure
                // metric or logs with it.
                if err.kind() != tokio::io::ErrorKind::NotFound {
                    metrics::CACHE_IO_FAILURE.increment();
                    error!(
                        "{log_prefix}failed to open partial file `{}`:  {err}",
                        path.display()
                    );
                }
            })?;

        let mdata = file.metadata().await.inspect_err(|err| {
            metrics::CACHE_IO_FAILURE.increment();
            error!(
                "{log_prefix}failed to get metadata of partial file `{}`:  {err}",
                path.display()
            );
        })?;
        if !mdata.file_type().is_file() {
            metrics::CACHE_NON_REGULAR.increment();
            warn!(
                "{log_prefix}partial file `{}` is not a regular file",
                path.display()
            );
            return Err(tokio::io::Error::new(
                tokio::io::ErrorKind::InvalidData,
                "Not a regular file",
            ));
        }

        // Seek to the end so subsequent writes append correctly.
        let size = file
            .seek(std::io::SeekFrom::End(0))
            .await
            .inspect_err(|err| {
                metrics::CACHE_IO_FAILURE.increment();
                error!(
                    "{log_prefix}failed to seek partial file `{}`:  {err}",
                    path.display()
                );
            })?;

        let mtime = mdata
            .modified()
            .expect("Platform should support modification timestamps via setup check");

        Ok((file, size, HttpDate::from(mtime)))
    }

    let path = partial_path_for_barrier(ibarrier);

    let guard = TempPath {
        path: Some(path),
        keep_on_drop: true,
    };
    match file_ops(&guard, log_prefix).await {
        Ok((file, size, mtime)) => Ok((file, size, mtime, guard)),
        Err(e) => Err((e, guard)),
    }
}

/// Create a new file at the given deterministic partial path, returning the file and a
/// `TempPath` guard with `keep_on_drop: true`.
pub(crate) async fn create_partial_file(
    guard: TempPath,
    mode: u32,
) -> Result<(tokio::fs::File, TempPath), (tokio::io::Error, PathBuf)> {
    async fn file_ops(path: &Path, mode: u32) -> Result<tokio::fs::File, tokio::io::Error> {
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }

        tokio::fs::File::options()
            .create(true)
            .truncate(true)
            .write(true)
            .read(true)
            .mode(mode)
            .custom_flags(nix::libc::O_NOFOLLOW)
            .open(path)
            .await
    }

    let path = guard.defuse();

    let file = match file_ops(&path, mode).await {
        Ok(file) => file,
        Err(err) => return Err((err, path)),
    };

    Ok((
        file,
        TempPath {
            path: Some(path),
            keep_on_drop: true,
        },
    ))
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
    let mdata = match file.metadata().await {
        Ok(m) => m,
        Err(err) => {
            error!(
                "Failed to get metadata of file `{}`:  {err}",
                display_path.display()
            );
            return file;
        }
    };
    // Cache entries are replaced on update, not overridden, so the creation time (btime)
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
            "Failed to update modification time of `{}`:  {err}",
            display_path.display()
        );
    }
    tokio::fs::File::from_std(std_file)
}

/// Hint to the kernel that `file` will be read sequentially from start to end,
/// so the page-cache readahead window can grow more aggressively.  Used on
/// every cache file we are about to stream to a client through the
/// hyper/sendfile paths.  Failure is non-fatal — the first failure is logged
/// at warn level (subsequent ones at debug) and we fall back to the kernel's
/// default readahead policy.
pub(crate) fn hint_sequential_read(file: &tokio::fs::File, display_path: &Path) {
    use nix::fcntl::{PosixFadviseAdvice, posix_fadvise};

    // Avoid using `tokio::task::block_in_place`, since no real I/O is involved
    if let Err(errno) = posix_fadvise(file, 0, 0, PosixFadviseAdvice::POSIX_FADV_SEQUENTIAL) {
        warn_once_or_debug!(
            "posix_fadvise(SEQUENTIAL) failed for `{}`:  {errno}",
            display_path.display()
        );
    }
}
