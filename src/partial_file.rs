//! Partial-download file lifecycle: the `.partial` file a permanent download
//! is written to, the random temp file a volatile one uses, and the
//! [`TempPath`] guard that decides what happens to either on drop.
//!
//! One download runs `InitBarrier` (`guards.rs`) -> [`prepare_partial_resume`]
//! (open or reserve the `.partial`) -> [`PartialDownload::into_target`]
//! ([`create_partial_file`] / [`tokio_tempfile`], one funnel for every
//! backend) -> `RenameBarrier::commit` (`guards.rs`), which consumes
//! the [`TempPath`] on the atomic rename. The `.partial` lives in the `tmp/`
//! sibling of the rename target ([`CachePaths::partial_file`]) so that rename
//! never crosses a filesystem.
//!
//! [`prepare_partial_resume`] claims the `.partial` path before it touches it
//! (`partial_claim`), and every guard over a kept partial carries that claim,
//! so cleanup's `tmp/` reap leaves the file alone for as long as the download
//! may still use it.

use std::{
    ops::Deref,
    path::{Path, PathBuf},
    sync::Arc,
};

use rand::{RngExt as _, distr::Alphanumeric, rngs::SmallRng};
use tracing::{debug, error, info, warn};

use crate::{
    Never,
    cache_metadata::{TargetFile, UpstreamMetadata},
    cache_paths::CachePaths,
    cache_quota::{CacheQuota, ReservedPartial, partial_len},
    deb_mirror,
    error::ErrorReport,
    fs_open::tokio_nofollow_options,
    global_cache_quota,
    guards::InitBarrier,
    http_etag::ETag,
    http_last_modified::LastModified,
    humanfmt::HumanFmt,
    metrics,
    partial_claim::PartialClaim,
    transfer_error::CacheError,
    warn_once_or_info, xattr_helpers,
};

/// Tri-state of an in-progress download's partial-file handling.
///
/// - `Volatile`: non-permanent cache flavor — no partial-file semantics; caller creates a
///   random temp file for the download.
/// - `Fresh`: permanent cache flavor with no valid existing partial; the guard reserves
///   the deterministic partial path so a failed download can be resumed on the next attempt.
/// - `Resumable`: permanent cache flavor with an existing valid partial whose file handle
///   has been held open since the size/ETag check (avoiding TOCTOU); caller resumes from
///   `file`'s current offset. `stored` holds the validators the first attempt persisted
///   on the partial (its `ETag` is always set: it is what made the partial resumable),
///   read through the same descriptor; see [`Self::resumed_validators`].
///
/// The `Resumable` handle is opened once, up front, so size and mtime come
/// from the same descriptor the download then writes through — there is no
/// window between the check and the open for the file to be replaced in.
/// Both guards are `OnDrop::Keep`: a partial survives a transient failure
/// (upstream 5xx, a fallback to another backend) and is picked up by the next
/// attempt. Discarding one is always explicit — [`Self::discard_resume`] for
/// a stale partial (a 200 answering an unsupported `Range`, a 416, an invalid
/// `Content-Range`), `TempPath::remove_blocking` for known-bad bytes.
pub(crate) enum PartialDownload {
    Volatile,
    Fresh(TempPath),
    Resumable {
        file: tokio::fs::File,
        guard: TempPath,
        stored: UpstreamMetadata,
    },
}

impl PartialDownload {
    /// Downgrade a `Resumable` state to `Fresh` by removing the stale partial file and
    /// re-creating the guard for the same path.  No-op for `Fresh` and `Volatile`.
    pub(crate) async fn discard_resume(&mut self) {
        *self = match std::mem::replace(self, Self::Volatile) {
            Self::Volatile => Self::Volatile,
            Self::Fresh(guard) => Self::Fresh(guard),
            Self::Resumable {
                file,
                guard,
                stored: _,
            } => {
                drop(file);
                Self::Fresh(guard.renew().await)
            }
        };
    }

    /// The validators the partial's first attempt stored, while the download
    /// still resumes it: `Some` only for `Resumable`, which a resume anomaly
    /// has already downgraded (see [`Self::discard_resume`]) by the time the
    /// upstream's answer is a usable `206`. Both backends hand this to
    /// [`UpstreamMetadata::inherit_resumed`].
    pub(crate) fn resumed_validators(&self) -> Option<&UpstreamMetadata> {
        match self {
            Self::Resumable {
                file: _,
                guard: _,
                stored,
            } => Some(stored),
            Self::Fresh(_) | Self::Volatile => None,
        }
    }

    /// The partial a quota reservation for this download accounts (see
    /// `cache_quota`'s module doc): `None` for a volatile scratch file, which
    /// is never kept; a `Resumable` partial's `resume_offset` bytes are
    /// adopted from the kept partial. It shares the guard's claim on the
    /// path, which the reservation's drop still measures.
    pub(crate) fn reserved_partial(&self, resume_offset: u64) -> Option<ReservedPartial> {
        match self {
            Self::Volatile => None,
            Self::Fresh(guard) => guard.claim().map(|claim| ReservedPartial::new(claim, 0)),
            Self::Resumable {
                file: _,
                guard,
                stored: _,
            } => guard
                .claim()
                .map(|claim| ReservedPartial::new(claim, resume_offset)),
        }
    }

    /// What [`Self::into_target`] hands back, for
    /// `cache_metadata::write_upstream_metadata`: only a resumed partial
    /// can carry xattrs of an earlier attempt; a `Fresh` partial is created
    /// with `O_EXCL` ([`create_partial_file`]) and a volatile temp file
    /// likewise ([`tokio_tempfile`]).
    pub(crate) fn target_file(&self) -> TargetFile {
        match self {
            Self::Resumable {
                file: _,
                guard: _,
                stored: _,
            } => TargetFile::Resumed,
            Self::Fresh(_) | Self::Volatile => TargetFile::New,
        }
    }

    /// Open or create the file the body is written into, taking over the path
    /// guard. The one place the `Resumable`/`Fresh`/`Volatile` sequence lives,
    /// so both fetching backends agree on the resume check, the modes and the
    /// operation names; the caller's download runner reports the failure.
    ///
    /// A `Resumable` whose length disagrees with `resume_offset` is a
    /// consistency failure, not a syscall failure: it builds a
    /// [`CacheError::invalid`] and leaves `CACHE_IO_FAILURE` alone.
    pub(crate) async fn into_target(
        self,
        filename: &Path,
        resume_offset: u64,
    ) -> Result<(tokio::fs::File, TempPath), CacheError> {
        use tokio::io::AsyncSeekExt as _;

        match self {
            Self::Resumable {
                mut file,
                guard,
                stored: _,
            } => {
                let size = file.seek(std::io::SeekFrom::End(0)).await.map_err(|err| {
                    CacheError::counted_io("seek partial cache file", &guard, err)
                })?;
                if size != resume_offset {
                    return Err(CacheError::invalid(
                        "validate resumed partial size",
                        format!("file has {size} bytes; expected {resume_offset}"),
                    ));
                }
                Ok((file, guard))
            }
            Self::Fresh(guard) => create_partial_file(guard, 0o640).await,
            Self::Volatile => {
                let path = CachePaths::global().scratch_file(filename);
                tokio_tempfile(&path, 0o640).await
            }
        }
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
/// a stored upstream `ETag` that is strong (no `W/`).  RFC 9110 §13.1.5
/// forbids a weak entity tag in `If-Range`, and §8.8.2.2 requires a strong
/// validator for it; `Last-Modified` / mtime are weak when the origin does not
/// guarantee sub-second-unique change detection — Debian mirror infrastructure
/// does not — and the stored total-size xattr is insufficient to detect a
/// same-size replacement within the mtime granularity.  Partials without an
/// `ETag` are therefore discarded rather than risk silent concatenation of
/// bytes from two different upstream revisions.
///
/// `log_prefix` is prepended to every emitted log line (e.g. `""` for the
/// hyper path, `"splice proxy: "` for the splice path).
///
/// The path is claimed first (see `partial_claim`): the returned guard holds
/// the claim, so cleanup does not reap a partial this download may still use.
/// A path another download still claims -- the tail of an earlier download
/// of the same file, whose registry entry was retired before its partial
/// guard or reservation dropped -- is not waited for: the download goes to a
/// scratch file like a volatile one, never touching the partial.
///
/// Returns `Ok` for the resumable, fresh and scratch outcomes; the caller
/// distinguishes via `partial`/`offset`.  The `Err` cases are the two ways the
/// partial file could not be opened, see [`PartialOpenFailure`]; the partial
/// path is left untouched on the filesystem either way.
pub(crate) async fn prepare_partial_resume(
    ibarrier: &InitBarrier,
    debname: &str,
    mirror: &deb_mirror::Mirror,
    log_prefix: &'static str,
) -> Result<PartialResume, PartialOpenFailure> {
    let path = partial_path_for_barrier(CachePaths::global(), ibarrier);
    let quota = Some(global_cache_quota().clone());
    prepare_partial_resume_at(path, quota, debname, mirror, log_prefix).await
}

/// [`prepare_partial_resume`] for an already-derived partial `path` and the
/// quota a removal of it releases bytes from: the pure half, kept free of
/// the global lookups so the lifecycle is unit-testable against a temporary
/// directory.
async fn prepare_partial_resume_at(
    path: PathBuf,
    quota: Option<CacheQuota>,
    debname: &str,
    mirror: &deb_mirror::Mirror,
    log_prefix: &'static str,
) -> Result<PartialResume, PartialOpenFailure> {
    let Some(claim) = PartialClaim::acquire(path.clone()) else {
        metrics::PARTIAL_CLAIM_CONTENDED.increment();
        warn_once_or_info!(
            "{log_prefix}partial download `{}` for {debname} from mirror {mirror} is still held by an earlier download of it; downloading into a scratch file without resuming",
            path.display()
        );
        return Ok(PartialResume::volatile());
    };
    match open_partial_file(claim, quota).await {
        Ok((file, size, guard)) if size > 0 => {
            if let Some(if_range) =
                xattr_helpers::read::<ETag>(&file, &guard).filter(ETag::is_strong)
            {
                let if_range = if_range.into_string();
                let last_modified = xattr_helpers::read::<LastModified>(&file, &guard)
                    .map(LastModified::into_parts)
                    .map(|(raw, time)| (Arc::from(raw), time));
                let stored = UpstreamMetadata {
                    etag: Some(Arc::from(if_range.as_str())),
                    last_modified,
                };
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
                    partial: PartialDownload::Resumable {
                        file,
                        guard,
                        stored,
                    },
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
        // Absence is the overwhelmingly common case and not a failure: start
        // a fresh download on the guard rather than making both backends
        // undo an `Err` identically.
        Err(PartialOpenError::NotFound(guard)) => Ok(PartialResume::fresh(guard)),
        Err(PartialOpenError::Failed { failure, guard }) => {
            Err(PartialOpenFailure { failure, guard })
        }
    }
}

/// Why `open_partial_file` did not hand back a resumable file. Internal:
/// `NotFound` never leaves this module, since [`prepare_partial_resume`]
/// turns it into a fresh download.
#[derive(Debug)]
enum PartialOpenError {
    /// No partial file at the path: the normal fresh-download case, not
    /// logged and not counted.
    NotFound(TempPath),
    /// Any other open/stat/seek failure. The operation counts cache failures;
    /// the guarded download owner retains and reports the cause.
    Failed {
        failure: CacheError,
        guard: TempPath,
    },
}

/// [`prepare_partial_resume`] could not open the deterministic partial path,
/// retaining its cache source for the guarded download runner. Hands back the
/// `TempPath` guard
/// (`OnDrop::Keep`, so dropping it touches nothing on disk).
#[derive(Debug)]
pub(crate) struct PartialOpenFailure {
    pub(crate) failure: CacheError,
    pub(crate) guard: TempPath,
}

/// What [`TempPath`]'s `Drop` does with the file it guards.
#[derive(Debug)]
enum OnDrop {
    /// Leave it on disk: a `.partial` at its deterministic path, which a
    /// retried download resumes from. The guard holds the download's claim
    /// on the path until it drops.
    Keep(PartialClaim),
    /// Unlink it: a scratch file with a randomised name that nothing can
    /// find again.
    Remove,
}

/// A guard over a temporary file path.
///
/// The two shapes are minted by [`TempPath::keeping`] and
/// [`TempPath::scratch`]; which one a path is depends on whether anything can
/// find it again, so the choice belongs to the constructor rather than to a
/// flag a caller sets.
pub(crate) struct TempPath {
    path: Option<PathBuf>,
    on_drop: OnDrop,
    /// The quota a kept `.partial` is accounted in (see `cache_quota`'s
    /// module doc): an explicit removal releases its bytes there. `None` for
    /// a scratch file, which is never accounted, and in unit tests.
    quota: Option<CacheQuota>,
}

impl TempPath {
    /// Guard the claimed deterministic `.partial` path: `Drop` leaves the
    /// file for a later resume and releases the claim.
    fn keeping(claim: PartialClaim, quota: Option<CacheQuota>) -> Self {
        Self {
            path: Some(claim.path().to_path_buf()),
            on_drop: OnDrop::Keep(claim),
            quota,
        }
    }

    /// Guard a randomly-named scratch file: `Drop` unlinks it, since nothing
    /// else knows the name.
    fn scratch(path: PathBuf) -> Self {
        Self {
            path: Some(path),
            on_drop: OnDrop::Remove,
            quota: None,
        }
    }

    /// The download's claim on a kept partial's path; `None` for a scratch
    /// file.
    fn claim(&self) -> Option<PartialClaim> {
        match &self.on_drop {
            OnDrop::Keep(claim) => Some(claim.clone()),
            OnDrop::Remove => None,
        }
    }

    /// Defuse the temporary path guard, returning the underlying `PathBuf`.
    pub(crate) fn defuse(mut self) -> PathBuf {
        std::mem::take(&mut self.path).expect("path has not been taken yet")
    }

    /// Force deletion of the underlying file regardless of [`OnDrop`],
    /// releasing a kept partial's bytes from the quota.
    ///
    /// Used for a partial whose content is known to be bad (checksum
    /// mismatch): keeping it would only feed a resume of the same wrong
    /// bytes. Readers still holding the open file are unaffected by the
    /// unlink.
    ///
    /// Blocking, for a caller already running in a blocking job; the claim
    /// on the path is released only after the unlink.
    pub(crate) fn remove_blocking(mut self) -> PathBuf {
        let path = std::mem::take(&mut self.path).expect("path has not been taken yet");
        remove_and_release(&path, self.quota.as_ref());
        path
    }

    /// Remove the underlying file and hand back the same guard, still
    /// `OnDrop::Keep` so a retried download can be resumed on failure. The
    /// claim is held throughout.
    async fn renew(self) -> Self {
        tokio::task::spawn_blocking(move || {
            remove_and_release(&self, self.quota.as_ref());
            self
        })
        .await
        .expect("partial removal should not panic")
    }
}

/// Unlink the partial at `path` and release the bytes it held from `quota`.
///
/// The size is read right before the unlink; the download's claim on the
/// path keeps every other writer, cleanup's reap included, off it in
/// between.
fn unlink_and_release(path: &Path, quota: Option<&CacheQuota>) -> std::io::Result<()> {
    // A missing partial fails the unlink below.
    let len = partial_len(path);
    std::fs::remove_file(path)?;
    if let Some(quota) = quota {
        quota.release_removed_partial(len);
    }
    Ok(())
}

/// [`unlink_and_release`] for an explicit removal, logging a failure.
fn remove_and_release(path: &Path, quota: Option<&CacheQuota>) {
    if let Err(err) = unlink_and_release(path, quota) {
        // NotFound is still a WARN here: the path is supposed to exist for the
        // lifetime of the TempPath guard, so a missing file means something
        // outside us deleted it (operator, FS issue): cleanup leaves a
        // claimed partial alone.
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
}

impl std::fmt::Debug for TempPath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self {
            path,
            on_drop,
            quota,
        } = self;
        f.debug_struct("TempPath")
            .field("path", path)
            .field("on_drop", on_drop)
            .field("accounted", &quota.is_some())
            .finish()
    }
}

impl Drop for TempPath {
    fn drop(&mut self) {
        if let Some(path) = self.path.take() {
            if matches!(self.on_drop, OnDrop::Keep(_)) {
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

/// Appended to a `debname` to name its resumable download in the mirror's
/// `tmp/` directory; `cache_layout::MAX_DEBNAME_LEN` reserves room for it.
pub(crate) const PARTIAL_SUFFIX: &str = ".partial";

/// Create a readable/writable temporary file with a unique extension.
/// Splice demotion duplicates this descriptor to read the growing file without
/// reopening its pathname.
pub(crate) async fn tokio_tempfile(
    path: &Path,
    mode: u32,
) -> Result<(tokio::fs::File, TempPath), CacheError> {
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
            .read(true)
            .write(true)
            .mode(mode)
            .open(&buf)
            .await
        {
            Ok(file) => {
                return Ok((file, TempPath::scratch(buf)));
            }
            Err(err) if err.kind() == tokio::io::ErrorKind::AlreadyExists => {
                tries += 1;
                if tries > MAX_RETRIES {
                    return Err(CacheError::counted_io(
                        "create temporary cache file",
                        &buf,
                        err,
                    ));
                }
                assert!(
                    buf.set_extension(""),
                    "buf is non-empty so removing an existing extension must succeed"
                );
                continue;
            }
            Err(err) => {
                return Err(CacheError::counted_io(
                    "create temporary cache file",
                    &buf,
                    err,
                ));
            }
        };
    }
}

/// Build the deterministic on-disk path for a download's `.partial` temp
/// file under `paths`: [`CachePaths::partial_file`] for the download's layout and site,
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
fn partial_path_for_barrier(paths: CachePaths<'_>, ibarrier: &InitBarrier) -> PathBuf {
    let filename = format!("{debname}{PARTIAL_SUFFIX}", debname = ibarrier.debname());
    paths.partial_file(ibarrier.layout(), ibarrier.site(), Path::new(&filename))
}

/// Open the existing partial file at the claimed path for writing at the end,
/// returning the file, its current size, and an `OnDrop::Keep` `TempPath`
/// guard holding the claim.
///
/// Uses `write(true)` + seek instead of `append(true)` so that splice(2) can use explicit
/// file offsets (`O_APPEND` is incompatible with splice's offset parameter).
///
/// By opening the file and querying size from the same file handle, this avoids
/// TOCTOU races between a separate `metadata()` check and a later `open()`.
async fn open_partial_file(
    claim: PartialClaim,
    quota: Option<CacheQuota>,
) -> Result<(tokio::fs::File, u64, TempPath), PartialOpenError> {
    use tokio::io::AsyncSeekExt as _;

    /// [`PartialOpenError`] before the guard is attached.
    enum FileOpsError {
        NotFound,
        Failed(CacheError),
    }

    async fn file_ops(path: &Path) -> Result<(tokio::fs::File, u64), FileOpsError> {
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
                    FileOpsError::Failed(CacheError::counted_io("open partial file", path, err))
                }
            })?;

        let mdata = file.metadata().await.map_err(|err| {
            FileOpsError::Failed(CacheError::counted_io(
                "get metadata of partial file",
                path,
                err,
            ))
        })?;
        if !mdata.file_type().is_file() {
            metrics::CACHE_NON_REGULAR.increment();
            return Err(FileOpsError::Failed(CacheError::invalid(
                "partial file metadata",
                format!("{} is not a regular file", path.display()),
            )));
        }

        // Seek to the end so subsequent writes append correctly.
        let size = file.seek(std::io::SeekFrom::End(0)).await.map_err(|err| {
            FileOpsError::Failed(CacheError::counted_io("seek partial file", path, err))
        })?;

        Ok((file, size))
    }

    let guard = TempPath::keeping(claim, quota);
    match file_ops(&guard).await {
        Ok((file, size)) => Ok((file, size, guard)),
        Err(FileOpsError::NotFound) => Err(PartialOpenError::NotFound(guard)),
        Err(FileOpsError::Failed(failure)) => Err(PartialOpenError::Failed { failure, guard }),
    }
}

/// Create a new file at the given deterministic partial path, returning the file and a
/// `OnDrop::Keep` `TempPath` guard. A failure names the path whose syscall
/// failed: the partial itself, or the parent directory it had to create.
///
/// A file already at the path (the empty partial a `Fresh` download reuses,
/// e.g. one a splice `416` or an attempt that failed before its first byte
/// left behind) is unlinked and replaced, not truncated: the download must
/// start on a new inode, or it would inherit the old attempt's creation date
/// -- which a synthesized `Last-Modified` reports -- and any xattrs it wrote.
pub(crate) async fn create_partial_file(
    guard: TempPath,
    mode: u32,
) -> Result<(tokio::fs::File, TempPath), CacheError> {
    async fn open(path: &Path, mode: u32) -> Result<tokio::fs::File, tokio::io::Error> {
        tokio_nofollow_options()
            .create_new(true)
            .write(true)
            .read(true)
            .mode(mode)
            .open(path)
            .await
    }

    async fn file_ops(
        path: &Path,
        mode: u32,
        quota: Option<CacheQuota>,
    ) -> Result<tokio::fs::File, CacheError> {
        let create = |err| CacheError::counted_io("create partial cache file", path, err);
        // Open first and create the parent only on `ENOENT`: with `O_CREAT`
        // set, a missing directory is the sole source of that errno here,
        // and the directory already exists for every download after the
        // first into a given `tmp/`. `create_dir_all` is a blocking-pool
        // round trip of its own, so the steady state now costs one hop
        // rather than two.
        // A leftover file costs the same extra hop: unlink it (a symlink
        // planted there included -- `O_EXCL` does not follow it), releasing
        // whatever it held from the quota, and create afresh.
        match open(path, mode).await {
            Err(err) if err.kind() == tokio::io::ErrorKind::NotFound => {
                if let Some(parent) = path.parent() {
                    tokio::fs::create_dir_all(parent).await.map_err(|err| {
                        CacheError::counted_io("create partial cache directory", parent, err)
                    })?;
                }
            }
            Err(err) if err.kind() == tokio::io::ErrorKind::AlreadyExists => {
                let leftover = path.to_path_buf();
                let unlinked = tokio::task::spawn_blocking(move || {
                    unlink_and_release(&leftover, quota.as_ref())
                })
                .await
                .expect("partial removal should not panic");
                match unlinked {
                    Err(err) if err.kind() == tokio::io::ErrorKind::NotFound => {}
                    result => result.map_err(|err| {
                        CacheError::counted_io("remove leftover partial cache file", path, err)
                    })?,
                }
            }
            result => return result.map_err(create),
        }

        open(path, mode).await.map_err(create)
    }

    // The guard, and so the download's claim on the path, stays alive
    // across the leftover's unlink and the create.
    let file = file_ops(&guard, mode, guard.quota.clone()).await?;
    Ok((file, guard))
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::io::AsyncWriteExt as _;

    use super::*;
    use crate::cache_quota::QUOTA_BLOCK_SIZE;
    use crate::{test_support::structured_mirror, xattr_helpers::tests::plant_raw};

    /// `TempPath::drop` unlinks on the blocking pool; wait for it to land.
    async fn wait_until_absent(path: &Path) -> bool {
        for _ in 0..1000 {
            if !path.exists() {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        false
    }

    fn partial_path(dir: &tempfile::TempDir) -> PathBuf {
        dir.path().join("mirror/tmp/foo_1.0_amd64.deb.partial")
    }

    /// The guard of a fresh download; any other state fails the test with
    /// `why` it should have been fresh.
    fn expect_fresh(partial: PartialDownload, why: &str) -> TempPath {
        let guard = match partial {
            PartialDownload::Fresh(guard) => Some(guard),
            PartialDownload::Volatile | PartialDownload::Resumable { .. } => None,
        };
        assert!(guard.is_some(), "expected a fresh download: {why}");
        guard.expect("asserted above")
    }

    /// Claim `path` as a download does before touching it.
    fn claim(path: &Path) -> PartialClaim {
        PartialClaim::acquire(path.to_path_buf()).expect("unclaimed partial")
    }

    /// The claim `prepare_partial_resume` takes lives in the partial's guard
    /// and in the quota reservation built from it, and ends with the later
    /// of the two: until then no second download (and no cleanup reap) can
    /// take the path.
    #[tokio::test]
    async fn the_claim_lasts_until_guard_and_reservation_are_gone() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = partial_path(&dir);
        let mirror = structured_mirror("deb.example.org", "debian");

        let resume =
            prepare_partial_resume_at(path.clone(), None, "foo_1.0_amd64.deb", &mirror, "")
                .await
                .expect("no partial is a fresh download");
        let reserved = resume.partial.reserved_partial(0).expect("a kept partial");
        let guard = expect_fresh(resume.partial, "no partial on disk");
        assert!(PartialClaim::acquire(path.clone()).is_none(), "claimed");

        drop(guard);
        assert!(
            PartialClaim::acquire(path.clone()).is_none(),
            "the reservation still measures the path"
        );
        drop(reserved);
        assert!(PartialClaim::acquire(path).is_some(), "released");
    }

    /// A path another download still claims (a double claim) is not a
    /// panic: the download goes to a scratch file and leaves the partial,
    /// and its resume state, untouched.
    #[tokio::test]
    async fn a_claimed_partial_degrades_the_download_to_a_scratch_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = partial_path(&dir);
        std::fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
        std::fs::write(&path, b"somebody's resume state").expect("write");
        let mirror = structured_mirror("deb.example.org", "debian");
        let held = claim(&path);

        let before = metrics::PARTIAL_CLAIM_CONTENDED.get();
        let resume =
            prepare_partial_resume_at(path.clone(), None, "foo_1.0_amd64.deb", &mirror, "")
                .await
                .expect("a scratch download, not a failure");
        assert_eq!(resume.offset, 0);
        assert!(matches!(resume.partial, PartialDownload::Volatile));
        assert!(resume.partial.reserved_partial(0).is_none());
        assert_eq!(metrics::PARTIAL_CLAIM_CONTENDED.get(), before + 1);
        assert_eq!(
            std::fs::read(&path).expect("read"),
            b"somebody's resume state"
        );
        drop(held);
    }

    /// A failed `lstat(2)` before the unlink leaves the partial's bytes
    /// unreleased; that must be reported, not read as an empty file. A path
    /// below a regular file fails with `ENOTDIR`, standing in for an `EIO`.
    #[test]
    fn unlink_and_release_reports_a_failed_stat() {
        let dir = tempfile::tempdir().expect("tempdir");
        let file = dir.path().join("file");
        std::fs::write(&file, b"x").expect("seed");
        let before = metrics::CACHE_IO_FAILURE.get();
        assert!(unlink_and_release(&file.join("x.partial"), None).is_err());
        assert_eq!(
            metrics::CACHE_IO_FAILURE.get() - before,
            1,
            "the failed stat is counted"
        );

        // A missing partial is nothing to release, not an I/O failure (the
        // failed unlink is the caller's to report).
        let before = metrics::CACHE_IO_FAILURE.get();
        assert!(unlink_and_release(&dir.path().join("gone.partial"), None).is_err());
        assert_eq!(metrics::CACHE_IO_FAILURE.get(), before);
    }

    /// A resumed partial whose length disagrees with the resume offset is a
    /// consistency failure, not a syscall failure: no `CACHE_IO_FAILURE`.
    #[tokio::test]
    async fn into_target_rejects_a_size_mismatch_without_counting_io() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("x.partial");
        tokio::fs::write(&path, b"12345").await.expect("seed");
        let (file, _size, guard) = open_partial_file(claim(&path), None).await.expect("reopen");
        let before = metrics::CACHE_IO_FAILURE.get();
        let err = PartialDownload::Resumable {
            file,
            guard,
            stored: UpstreamMetadata::default(),
        }
        .into_target(Path::new("x.deb"), 4)
        .await
        .expect_err("5 != 4");
        assert_eq!(metrics::CACHE_IO_FAILURE.get(), before);
        assert!(
            err.to_string().contains("validate resumed partial size"),
            "{err}"
        );
    }

    #[tokio::test]
    async fn tempfile_create_failure_keeps_attempted_random_path() {
        let dir = tempfile::tempdir().expect("tempdir");
        let base = dir.path().join("missing/volatile");
        let before = metrics::CACHE_IO_FAILURE.get();
        let error = tokio_tempfile(&base, 0o640)
            .await
            .expect_err("missing parent");
        let report = ErrorReport(&error).to_string();
        let attempted = Path::new(report.split('`').nth(1).expect("quoted path"));
        assert_eq!(attempted.parent(), base.parent(), "{report}");
        assert_eq!(attempted.file_stem(), base.file_name(), "{report}");
        assert!(
            attempted.extension().is_some(),
            "random extension missing: {report}"
        );
        assert_eq!(
            report.matches("create temporary cache file").count(),
            1,
            "{report}"
        );
        assert_eq!(report.matches("(os error").count(), 1, "{report}");
        assert_eq!(metrics::CACHE_IO_FAILURE.get(), before + 1);
    }

    #[tokio::test]
    async fn tempfile_is_removed_on_drop_and_kept_after_defuse() {
        let dir = tempfile::tempdir().expect("tempdir");
        let base = dir.path().join("volatile");

        let (file, guard) = tokio_tempfile(&base, 0o640).await.expect("tempfile");
        let removed = guard.to_path_buf();
        assert_ne!(removed, base, "the temp file gets a random extension");
        assert!(removed.is_file(), "temp file exists while guarded");
        drop(file);
        drop(guard);
        assert!(
            wait_until_absent(&removed).await,
            "dropping the guard unlinks the temp file"
        );

        let (file, guard) = tokio_tempfile(&base, 0o640).await.expect("tempfile");
        let kept = guard.defuse();
        drop(file);
        assert!(kept.is_file(), "defuse hands the file over intact");
    }

    #[tokio::test]
    async fn partial_lifecycle_create_keep_reopen_remove() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = partial_path(&dir);

        let guard = match open_partial_file(claim(&path), None).await {
            Err(PartialOpenError::NotFound(guard)) => Some(guard),
            Ok(_) | Err(PartialOpenError::Failed { .. }) => None,
        }
        .expect("no partial exists yet");
        assert_eq!(&*guard, path.as_path());

        // create_partial_file creates the tmp/ parent and hands back a
        // keep-on-drop guard.
        let (mut file, guard) = create_partial_file(guard, 0o640)
            .await
            .expect("create partial");
        file.write_all(b"hello").await.expect("write");
        file.flush().await.expect("flush");
        drop(file);
        drop(guard);
        tokio::task::yield_now().await;
        assert!(path.is_file(), "a partial survives its guard");

        // Reopening lands at the end of the existing bytes.
        let (file, size, guard) = open_partial_file(claim(&path), None)
            .await
            .expect("partial reopens");
        assert_eq!(size, 5);
        drop(file);

        let returned = guard.remove_blocking();
        assert_eq!(returned, path);
        assert!(!path.exists(), "remove unlinks regardless of OnDrop");
        assert!(
            PartialClaim::acquire(path).is_some(),
            "the removed guard's claim is released"
        );
    }

    /// A leftover file at the partial path is replaced by a new inode, not
    /// truncated in place: the old one's creation date and xattrs must not
    /// reach the new download.
    // The xattr read runs through `block_in_place`, which needs the
    // multi-thread runtime.
    #[tokio::test(flavor = "multi_thread")]
    async fn create_partial_file_replaces_a_leftover_instead_of_truncating_it() {
        use std::os::unix::fs::MetadataExt as _;

        let dir = tempfile::tempdir().expect("tempdir");
        let path = partial_path(&dir);
        std::fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
        std::fs::write(&path, b"").expect("write");
        // Held open across the call, so the old inode stays allocated and its
        // number cannot be handed straight back to the new file.
        let leftover = std::fs::File::open(&path).expect("open leftover");
        let planted = plant_raw::<ETag>(&leftover, b"\"old\"");
        let old_ino = leftover.metadata().expect("stat leftover").ino();

        let (file, guard) = create_partial_file(TempPath::keeping(claim(&path), None), 0o640)
            .await
            .expect("create over a leftover");
        assert_eq!(&*guard, path.as_path());
        assert_ne!(
            file.metadata().await.expect("stat new").ino(),
            old_ino,
            "the download starts on a new inode"
        );
        if planted {
            assert!(
                xattr_helpers::read::<ETag>(&file, &path).is_none(),
                "the leftover's xattrs stay with the leftover"
            );
        }
        drop(leftover);
    }

    #[tokio::test]
    async fn open_partial_file_rejects_a_non_regular_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = partial_path(&dir);
        std::fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
        nix::unistd::mkfifo(&path, nix::sys::stat::Mode::S_IRWXU).expect("mkfifo");

        let before = metrics::CACHE_NON_REGULAR.get();
        let guard = match open_partial_file(claim(&path), None).await {
            Err(PartialOpenError::Failed { failure: _, guard }) => Some(guard),
            Ok(_) | Err(PartialOpenError::NotFound(_)) => None,
        }
        .expect("a FIFO is not a partial");
        assert!(
            metrics::CACHE_NON_REGULAR.get() > before,
            "the anomaly is counted"
        );
        drop(guard);
        tokio::task::yield_now().await;
        assert!(path.exists(), "the guard keeps the path untouched");
    }

    // The xattr read runs through `block_in_place`, which needs the
    // multi-thread runtime.
    #[tokio::test(flavor = "multi_thread")]
    async fn prepare_partial_resume_discards_a_partial_without_etag() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = partial_path(&dir);
        std::fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
        std::fs::write(&path, b"stale").expect("write");
        let mirror = structured_mirror("deb.example.org", "debian");

        let resume =
            prepare_partial_resume_at(path.clone(), None, "foo_1.0_amd64.deb", &mirror, "")
                .await
                .expect("a discarded partial is a fresh download");
        assert_eq!(resume.offset, 0);
        assert_eq!(resume.expected_total, None);
        assert_eq!(resume.if_range, None);
        let guard = expect_fresh(resume.partial, "no ETag means no resume");
        assert!(!path.exists(), "the stale partial is unlinked");
        assert_eq!(&*guard, path.as_path(), "the guard still reserves the path");
    }

    // The xattr read runs through `block_in_place`, which needs the
    // multi-thread runtime.
    #[tokio::test(flavor = "multi_thread")]
    async fn prepare_partial_resume_discards_a_partial_with_a_weak_etag() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = partial_path(&dir);
        std::fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
        std::fs::write(&path, b"partial-bytes").expect("write");
        let std_file = std::fs::File::open(&path).expect("open");
        if !plant_raw::<ETag>(&std_file, b"W/\"weak\"") {
            // Filesystem without user xattrs: nothing to gate on here.
            return;
        }
        drop(std_file);
        let mirror = structured_mirror("deb.example.org", "debian");

        let resume =
            prepare_partial_resume_at(path.clone(), None, "foo_1.0_amd64.deb", &mirror, "")
                .await
                .expect("a discarded partial is a fresh download");
        assert_eq!(resume.offset, 0);
        assert_eq!(
            resume.if_range, None,
            "a weak tag must never be sent as If-Range"
        );
        assert!(
            matches!(resume.partial, PartialDownload::Fresh(_)),
            "a weak ETag makes the partial unresumable"
        );
        assert!(!path.exists(), "the stale partial is unlinked");
    }

    // The xattr read runs through `block_in_place`, which needs the
    // multi-thread runtime.
    #[tokio::test(flavor = "multi_thread")]
    async fn prepare_partial_resume_resumes_a_partial_with_etag() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = partial_path(&dir);
        std::fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
        std::fs::write(&path, b"partial-bytes").expect("write");
        let std_file = std::fs::File::open(&path).expect("open");
        if !plant_raw::<ETag>(&std_file, b"\"strong\"") {
            // Filesystem without user xattrs: the resume branch cannot be
            // exercised here.
            return;
        }
        let stored_lm = "Thu, 01 Jan 2004 00:00:00 GMT";
        assert!(
            plant_raw::<LastModified>(&std_file, stored_lm.as_bytes()),
            "the ETag planted, so the Last-Modified attribute must too"
        );
        drop(std_file);
        let mirror = structured_mirror("deb.example.org", "debian");

        let mut resume =
            prepare_partial_resume_at(path.clone(), None, "foo_1.0_amd64.deb", &mirror, "")
                .await
                .expect("the partial reopens");
        assert_eq!(resume.offset, 13);
        assert_eq!(resume.expected_total, None, "no expected-size xattr");
        assert_eq!(resume.if_range.as_deref(), Some("\"strong\""));
        assert!(
            matches!(resume.partial, PartialDownload::Resumable { .. }),
            "a strong ETag makes the partial resumable"
        );
        // Both stored validators ride along, for a `206` that omits them.
        assert_eq!(
            resume.partial.resumed_validators(),
            Some(&UpstreamMetadata::from_upstream(
                Some("\"strong\"".into()),
                Some(stored_lm.into())
            ))
        );

        // A rejected resume (416 upstream) downgrades to a fresh download on
        // the same path.
        resume.partial.discard_resume().await;
        assert!(
            matches!(resume.partial, PartialDownload::Fresh(_)),
            "discard_resume yields Fresh"
        );
        assert_eq!(
            resume.partial.resumed_validators(),
            None,
            "a discarded partial's validators describe nothing the download serves"
        );
        assert!(!path.exists(), "the stale partial is unlinked");
    }

    // The xattr reads run through `block_in_place`, which needs the
    // multi-thread runtime.
    #[tokio::test(flavor = "multi_thread")]
    async fn prepare_partial_resume_reports_the_expected_total_from_xattr() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = partial_path(&dir);
        std::fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
        std::fs::write(&path, b"partial-bytes").expect("write");
        let std_file = std::fs::File::open(&path).expect("open");
        if !plant_raw::<ETag>(&std_file, b"\"strong\"") {
            // Filesystem without user xattrs: the resume branch cannot be
            // exercised here.
            return;
        }
        assert!(
            plant_raw::<xattr_helpers::ExpectedSize>(&std_file, b"4096"),
            "the ETag planted, so the expected-size attribute must too"
        );
        drop(std_file);
        let mirror = structured_mirror("deb.example.org", "debian");

        let resume = prepare_partial_resume_at(path, None, "foo_1.0_amd64.deb", &mirror, "")
            .await
            .expect("the partial reopens");
        assert_eq!(resume.offset, 13);
        assert_eq!(
            resume.expected_total,
            Some(4096),
            "the stored total is what lets a resume detect an upstream size change"
        );
        assert_eq!(resume.if_range.as_deref(), Some("\"strong\""));
    }

    /// Every explicit unlink of a kept partial releases its bytes from the
    /// quota it is accounted in: a discarded resume and a replaced leftover
    /// alike.
    // The xattr read runs through `block_in_place`, which needs the
    // multi-thread runtime.
    #[tokio::test(flavor = "multi_thread")]
    async fn removing_a_kept_partial_releases_its_bytes() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = partial_path(&dir);
        std::fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
        std::fs::write(&path, b"stale").expect("write");
        let mirror = structured_mirror("deb.example.org", "debian");
        // Ten blocks of cached files plus the 5-byte kept partial, accounted
        // as one block.
        let quota = CacheQuota::new(11 * QUOTA_BLOCK_SIZE, None);

        // Without an ETag the partial is discarded.
        let resume = prepare_partial_resume_at(
            path.clone(),
            Some(quota.clone()),
            "foo_1.0_amd64.deb",
            &mirror,
            "",
        )
        .await
        .expect("a discarded partial is a fresh download");
        assert_eq!(quota.current_size(), 10 * QUOTA_BLOCK_SIZE);
        let guard = expect_fresh(resume.partial, "no ETag means no resume");

        std::fs::write(&path, b"leftover!").expect("plant leftover");
        let (file, guard) = create_partial_file(guard, 0o640)
            .await
            .expect("create over a leftover");
        assert_eq!(
            quota.current_size(),
            9 * QUOTA_BLOCK_SIZE,
            "the 9-byte leftover's block is released"
        );
        drop(file);
        drop(guard);
    }

    #[tokio::test]
    async fn prepare_partial_resume_treats_an_empty_partial_as_fresh() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = partial_path(&dir);
        std::fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
        std::fs::write(&path, b"").expect("write");
        let mirror = structured_mirror("deb.example.org", "debian");

        let resume =
            prepare_partial_resume_at(path.clone(), None, "foo_1.0_amd64.deb", &mirror, "")
                .await
                .expect("an empty partial is a fresh download");
        assert_eq!(resume.offset, 0);
        assert!(matches!(resume.partial, PartialDownload::Fresh(_)));
    }
}
