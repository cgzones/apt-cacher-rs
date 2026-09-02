use std::{
    num::NonZero,
    ops::Deref,
    path::{Path, PathBuf},
};

use rand::{RngExt as _, distr::Alphanumeric, rngs::SmallRng};
use tracing::{debug, error, info, warn};

use crate::{
    Never,
    cache_layout::{SUBDIR_FLAT, SUBDIR_TMP},
    config::CacheHost,
    deb_mirror,
    error::ErrorReport,
    global_config,
    guards::InitBarrier,
    http_etag::read_etag,
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
/// Proof that a failure was logged at its throw site.
///
/// `docs/logging.md`: a failure is logged once, at the site that decides the
/// outcome. Some sites must be that site because the context that makes the
/// line actionable -- the on-disk path, the upstream authority and attempt
/// count -- exists only there; the error variant they return then carries
/// this token instead of (or next to) the error, and the outer arm receiving
/// it maps silently. The field is private and the only constructors are the
/// logging helpers below, so such a variant cannot be thrown without its log
/// line, and a reviewer reading `Logged` at a throw site knows which helper
/// wrote it.
///
/// The helpers log from this module, so the `target` recorded for the line
/// (visible only in the web interface's log store, which prints targets) is
/// `utils`, not the throw site's module. The console/file sinks print no
/// target.
#[derive(Debug)]
pub(crate) struct Logged(());

impl Logged {
    /// `error!` the line and prove it.
    pub(crate) fn error(args: std::fmt::Arguments<'_>) -> Self {
        error!("{args}");
        Self(())
    }

    /// `warn!` the line and prove it.
    pub(crate) fn warn(args: std::fmt::Arguments<'_>) -> Self {
        warn!("{args}");
        Self(())
    }

    /// A cached-file syscall failed: bump `CACHE_IO_FAILURE` and `error!`
    /// the line (the pairing every cache-I/O throw site owes, per
    /// `CLAUDE.md`).
    pub(crate) fn cache_io_failure(args: std::fmt::Arguments<'_>) -> Self {
        metrics::CACHE_IO_FAILURE.increment();
        Self::error(args)
    }

    /// The body of [`crate::warn_once_or_info_logged!`]: `fired` is that
    /// call site's own once-gate, so per-site flood control is unchanged
    /// from [`crate::warn_once_or_info!`]. Call through the macro, never
    /// directly -- a shared gate would collapse every site into one.
    #[cfg(feature = "splice")]
    pub(crate) fn warn_once_or_info(
        fired: &'static std::sync::atomic::AtomicBool,
        args: std::fmt::Arguments<'_>,
    ) -> Self {
        use std::sync::atomic::Ordering::Relaxed;

        if !fired.load(Relaxed)
            && fired
                .compare_exchange(false, true, Relaxed, Relaxed)
                .is_ok()
        {
            warn!("{args}");
        } else {
            info!("{args}");
        }
        Self(())
    }
}

/// Marker for a cache-file access that failed and was already logged, with
/// the matching `CACHE_IO_FAILURE` / `CACHE_NON_REGULAR` bump. Callers only
/// map it to their transport's 500 - never log it a second time; the carried
/// [`Logged`] is the proof.
#[derive(Debug)]
pub(crate) struct CacheAccessFailure(pub(crate) Logged);

/// `fstat` an open cache file and require a regular file.
///
/// The single owner of the "stat failed -> `CACHE_IO_FAILURE`, non-regular ->
/// `CACHE_NON_REGULAR`" policy for files about to be served: every serve path
/// (hyper, sendfile, splice) goes through here so no path can silently skip
/// the anomaly accounting.
pub(crate) async fn regular_file_metadata(
    file: &tokio::fs::File,
    path: &Path,
) -> Result<std::fs::Metadata, CacheAccessFailure> {
    match file.metadata().await {
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

/// Returns `true` when `err` indicates the peer terminated the connection
/// (by reset, abort, half-close, or EOF). Used to demote routine "client
/// went away" log lines from warn to info, since they are not actionable
/// for the operator.
///
/// `ErrorKind::TimedOut` is deliberately *not* included here: in this
/// codebase, `TimedOut` `io::Error`s overwhelmingly originate from the
/// proxy's own decisions — `wait_socket_rated` HTTP per-op timeouts and
/// `rate_checked_body` rate-stalls — which already bump dedicated
/// `HTTP_TIMEOUT_*` counters at construction. Folding them into
/// "peer disconnect" was double-attributing them to
/// `CLIENT_DISCONNECTED_MID_BODY`. The rare OS-level `ETIMEDOUT`
/// (TCP keepalive / `TCP_USER_TIMEOUT`) is the only remaining source and
/// is acceptable to log as a warn-level timeout rather than an
/// info-level "peer disconnect" — the wording stays accurate either way.
///
/// Call sites that want to demote a `TimedOut` to a different severity
/// (e.g. the header-read idle-timeout debug path, or the splice
/// boundary-chunk demote-on-stall path) MUST add an explicit
/// `err.kind() == ErrorKind::TimedOut` branch before this check.
#[must_use]
pub(crate) fn is_peer_disconnect(err: &std::io::Error) -> bool {
    use std::io::ErrorKind;
    matches!(
        err.kind(),
        ErrorKind::BrokenPipe
            | ErrorKind::ConnectionAborted
            | ErrorKind::ConnectionReset
            | ErrorKind::NotConnected
            | ErrorKind::UnexpectedEof
    )
}

/// One `statvfs(3)` snapshot of a filesystem's remaining capacity.
///
/// Both figures are what an unprivileged process may still consume. They
/// fail independently in practice: a cache can be byte-rich and inode-poor
/// (a mirror of many tiny index files on a small-inode ext4) and then
/// `ENOSPC` arrives with gigabytes still free.
#[derive(Clone, Copy, Debug)]
pub(crate) struct FsSpace {
    /// Bytes available to unprivileged processes.
    pub(crate) free_bytes: u64,
    /// Inode accounting. `None` when the filesystem reports no inode limit
    /// at all (btrfs and other dynamically-allocating filesystems report a
    /// total of 0), which is not the same as "none left".
    pub(crate) inodes: Option<InodeSpace>,
}

/// Inode accounting of a filesystem that has a fixed inode table.
#[derive(Clone, Copy, Debug)]
pub(crate) struct InodeSpace {
    /// Inodes available to unprivileged processes.
    pub(crate) free: u64,
    /// Inodes the filesystem was created with.
    pub(crate) total: NonZero<u64>,
}

impl InodeSpace {
    /// Whether fewer than `1/divisor` of all inodes are still available.
    /// Integer math: no rounding surprises near the boundary.
    #[must_use]
    pub(crate) fn free_below_fraction(self, divisor: u64) -> bool {
        self.free.saturating_mul(divisor) < self.total.get()
    }
}

/// Remaining capacity of the filesystem holding `path`, via `statvfs(3)`.
/// Returns `None` when the blocking task is lost or the probe fails.
/// Free-byte accounting saturates at `u64::MAX` if the `statvfs` product
/// does not fit in `u64`. The blocking pool keeps a slow filesystem from
/// wedging a Tokio worker.
pub(crate) async fn filesystem_space(path: &Path) -> Option<FsSpace> {
    let owned = path.to_path_buf();
    let joined = tokio::task::spawn_blocking(move || nix::sys::statvfs::statvfs(&owned)).await;
    let result = match joined {
        Ok(result) => result,
        Err(err) => {
            warn_once_or_debug!(
                "Failed to join the statvfs(3) probe of `{}`; treating the free space as unknown:  {}",
                path.display(),
                ErrorReport(&err)
            );
            return None;
        }
    };
    let stat = result
        .inspect_err(|err| {
            warn_once_or_debug!(
                "Failed to statvfs(3) the filesystem holding `{}`; treating the free space as unknown:  {}",
                path.display(),
                ErrorReport(err)
            );
        })
        .ok()?;
    let free_bytes = stat.blocks_available().saturating_mul(stat.fragment_size());
    Some(FsSpace {
        free_bytes,
        inodes: NonZero::new(stat.files()).map(|total| InodeSpace {
            free: stat.files_available(),
            total,
        }),
    })
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
    /// A permanent file with no partial to resume: the download starts at
    /// byte 0 on the deterministic partial path `guard` reserves.
    pub(crate) fn fresh(guard: TempPath) -> Self {
        Self {
            offset: 0,
            expected_total: None,
            if_range: None,
            partial: PartialDownload::Fresh(guard),
        }
    }

    /// A volatile file: no partial-file semantics, the download starts at
    /// byte 0 into a random temp file.
    pub(crate) fn volatile() -> Self {
        Self {
            offset: 0,
            expected_total: None,
            if_range: None,
            partial: PartialDownload::Volatile,
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
/// distinguishes via `partial`/`offset`.  The `Err` cases are the two ways the
/// partial file could not be opened, see [`PartialOpenError`]; the partial
/// path is left untouched on the filesystem either way.
pub(crate) async fn prepare_partial_resume(
    ibarrier: &InitBarrier<'_>,
    debname: &str,
    mirror: &deb_mirror::Mirror,
    log_prefix: &'static str,
) -> Result<PartialResume, PartialOpenError> {
    match open_partial_file(ibarrier, log_prefix).await {
        Ok((file, size, guard)) if size > 0 => {
            if let Some(if_range) = read_etag(&file, &guard) {
                let expected_total = xattr_helpers::read_expected_size(&file, &guard);
                // The total is only known when the partial carries the
                // expected-size xattr; narrate its absence instead of
                // placeholdering it.
                if let Some(total) = expected_total {
                    info!(
                        "{log_prefix}found partial download ({} out of {}) for {debname} from mirror {mirror}, will attempt resume",
                        HumanFmt::Size(size),
                        HumanFmt::Size(total),
                    );
                } else {
                    info!(
                        "{log_prefix}found partial download ({}, total size unknown) for {debname} from mirror {mirror}, will attempt resume",
                        HumanFmt::Size(size),
                    );
                }

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
        Ok((_file, _size, guard)) => Ok(PartialResume::fresh(guard)),
        Err(err) => Err(err),
    }
}

/// Why [`prepare_partial_resume`] could not open the partial file. Both
/// variants hand back the `TempPath` guard for the deterministic partial path
/// (`keep_on_drop: true`, so dropping it touches nothing on disk).
pub(crate) enum PartialOpenError {
    /// No partial file at the path: the normal fresh-download case, not
    /// logged and not counted. The caller starts a fresh download on the guard.
    NotFound(TempPath),
    /// Any other open/stat/seek failure, logged inside `open_partial_file`
    /// with the path and the matching `CACHE_IO_FAILURE` / `CACHE_NON_REGULAR`
    /// bump; the caller answers 500 without logging again.
    Failed { logged: Logged, guard: TempPath },
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
        std::mem::take(&mut self.path).expect("path has not been taken yet")
    }

    /// Force deletion of the underlying file regardless of `keep_on_drop`.
    ///
    /// Used for a partial whose content is known to be bad (checksum
    /// mismatch): keeping it would only feed a resume of the same wrong
    /// bytes. Readers still holding the open file are unaffected by the
    /// unlink.
    pub(crate) async fn remove(mut self) -> PathBuf {
        let path = std::mem::take(&mut self.path).expect("path has not been taken yet");

        if let Err(err) = tokio::fs::remove_file(&path).await {
            // NotFound is still a WARN here: the path is supposed to exist for the
            // lifetime of the TempPath guard, so a missing file means something
            // outside us deleted it (operator, racing cleanup, FS issue).
            if err.kind() == std::io::ErrorKind::NotFound {
                warn!(
                    "Failed to remove partial file `{}`; continuing without it:  {}",
                    path.display(),
                    ErrorReport(&err)
                );
            } else {
                error!(
                    "Failed to remove partial file `{}`; it stays on disk:  {}",
                    path.display(),
                    ErrorReport(&err)
                );
            }
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
                        "Failed to remove temporary file `{}`; it stays on disk:  {}",
                        path.display(),
                        ErrorReport(&err)
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
        self.path.as_deref().expect("path has not been taken yet")
    }
}

impl AsRef<Path> for TempPath {
    fn as_ref(&self) -> &Path {
        self.path.as_deref().expect("path has not been taken yet")
    }
}

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

/// [`tokio::fs::OpenOptions`] with `O_NOFOLLOW` pre-set: every open of a path
/// under the cache directory must refuse a symlink at the final component.
/// Callers chain the remaining flags on the returned options.
///
/// `custom_flags` overwrites rather than ORs, so callers must NOT call
/// `.custom_flags()` again on the returned options.
pub(crate) fn tokio_nofollow_options() -> tokio::fs::OpenOptions {
    #[expect(
        clippy::disallowed_methods,
        reason = "single blessed construction site"
    )]
    let mut options = tokio::fs::OpenOptions::new();
    options.custom_flags(nix::libc::O_NOFOLLOW);
    options
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
        const MAX_RETRIES: u32 = 10;

        let s: String = (&mut rng)
            .sample_iter(Alphanumeric)
            .take(6)
            .map(char::from)
            .collect();

        assert!(
            buf.set_extension(s),
            "buf is non-empty so adding a new extension must succeed"
        );

        let _: Never = match tokio_nofollow_options()
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
                if tries > MAX_RETRIES {
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
/// (mirroring [`crate::cache_layout::ConnectionDetails::cache_dir_path`]); otherwise it is the
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
    // Resolve to the on-disk cache identity.  Mirrors the rule in
    // `ConnectionDetails::cache_dir_path` so the `.partial` lands next to the
    // eventual rename target.
    let host: &CacheHost = match ibarrier.aliased_host() {
        Some(cache) => cache,
        None => mirror.host().as_cache_host(),
    };
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
/// and a `TempPath` guard with `keep_on_drop: true`.
///
/// Uses `write(true)` + seek instead of `append(true)` so that splice(2) can use explicit
/// file offsets (`O_APPEND` is incompatible with splice's offset parameter).
///
/// By opening the file and querying size from the same file handle, this avoids
/// TOCTOU races between a separate `metadata()` check and a later `open()`.
async fn open_partial_file(
    ibarrier: &InitBarrier<'_>,
    log_prefix: &'static str,
) -> Result<(tokio::fs::File, u64, TempPath), PartialOpenError> {
    use tokio::io::AsyncSeekExt as _;

    /// [`PartialOpenError`] before the guard is attached.
    enum FileOpsError {
        NotFound,
        Failed(Logged),
    }

    async fn file_ops(
        path: &Path,
        log_prefix: &'static str,
    ) -> Result<(tokio::fs::File, u64), FileOpsError> {
        let mut file = tokio_nofollow_options()
            .write(true)
            .read(true)
            .open(path)
            .await
            .map_err(|err| {
                // NotFound is the normal "no partial file" case; the caller
                // turns it into a fresh download.  Don't pollute the failure
                // metric or logs with it.
                if err.kind() == tokio::io::ErrorKind::NotFound {
                    FileOpsError::NotFound
                } else {
                    FileOpsError::Failed(Logged::cache_io_failure(format_args!(
                        "{log_prefix}failed to open partial file `{}`; returning 500:  {}",
                        path.display(),
                        ErrorReport(&err)
                    )))
                }
            })?;

        let mdata = file.metadata().await.map_err(|err| {
            FileOpsError::Failed(Logged::cache_io_failure(format_args!(
                "{log_prefix}failed to get metadata of partial file `{}`; returning 500:  {}",
                path.display(),
                ErrorReport(&err)
            )))
        })?;
        if !mdata.file_type().is_file() {
            metrics::CACHE_NON_REGULAR.increment();
            return Err(FileOpsError::Failed(Logged::warn(format_args!(
                "{log_prefix}partial file `{}` is not a regular file; returning 500",
                path.display()
            ))));
        }

        // Seek to the end so subsequent writes append correctly.
        let size = file.seek(std::io::SeekFrom::End(0)).await.map_err(|err| {
            FileOpsError::Failed(Logged::cache_io_failure(format_args!(
                "{log_prefix}failed to seek partial file `{}`; returning 500:  {}",
                path.display(),
                ErrorReport(&err)
            )))
        })?;

        Ok((file, size))
    }

    let path = partial_path_for_barrier(ibarrier);

    let guard = TempPath {
        path: Some(path),
        keep_on_drop: true,
    };
    match file_ops(&guard, log_prefix).await {
        Ok((file, size)) => Ok((file, size, guard)),
        Err(FileOpsError::NotFound) => Err(PartialOpenError::NotFound(guard)),
        Err(FileOpsError::Failed(logged)) => Err(PartialOpenError::Failed { logged, guard }),
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

        tokio_nofollow_options()
            .create(true)
            .truncate(true)
            .write(true)
            .read(true)
            .mode(mode)
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
