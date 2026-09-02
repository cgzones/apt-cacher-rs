//! Partial-download file lifecycle: the `.partial` file a permanent download
//! is written to, the random temp file a volatile one uses, and the
//! [`TempPath`] guard that decides what happens to either on drop.
//!
//! One download runs `InitBarrier` (`guards.rs`) -> [`prepare_partial_resume`]
//! (open or reserve the `.partial`) -> [`create_partial_file`] /
//! [`tokio_tempfile`] -> `RenameBarrier::commit` (`guards.rs`), which consumes
//! the [`TempPath`] on the atomic rename. The `.partial` lives in the `tmp/`
//! sibling of the rename target ([`CachePaths::partial_file`]) so that rename
//! never crosses a filesystem.

use std::{
    ops::Deref,
    path::{Path, PathBuf},
};

use rand::{RngExt as _, distr::Alphanumeric, rngs::SmallRng};
use tracing::{debug, error, info, warn};

use crate::{
    Never, cache_paths::CachePaths, deb_mirror, error::ErrorReport,
    fs_open::tokio_nofollow_options, guards::InitBarrier, http_etag::ETag, humanfmt::HumanFmt,
    log_once::Logged, metrics, xattr_helpers,
};

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
            if let Some(if_range) = xattr_helpers::read::<ETag>(&file, &guard) {
                let if_range = if_range.into_string();
                let expected_total =
                    xattr_helpers::read::<xattr_helpers::ExpectedSize>(&file, &guard)
                        .map(|xattr_helpers::ExpectedSize(size)| size);
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
/// file: [`CachePaths::partial_file`] for the download's layout and site,
/// i.e. the `tmp/` sibling of the eventual rename target
/// (`{anchor}/tmp/{debname}.partial`), so the atomic `rename(2)` after the
/// download finishes stays within the same filesystem.
///
/// The site comes from [`InitBarrier::site`], which resolves the alias'
/// main host exactly like `ConnectionDetails::site` does for the rename
/// target; using the same host on both sides is what keeps the sibling
/// guarantee.  Disambiguation between flat-pool `.deb`s sharing a basename
/// across different sub-directories (`apt/amd64/foo.deb` vs
/// `apt/arm64/foo.deb`) is implicit in the site's mirror path, which equals
/// the URL-dir verbatim under the host-anchored flat layout.
fn partial_path_for_barrier(ibarrier: &InitBarrier<'_>) -> PathBuf {
    let filename = format!("{debname}.partial", debname = ibarrier.debname());
    CachePaths::global().partial_file(ibarrier.layout(), ibarrier.site(), Path::new(&filename))
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
