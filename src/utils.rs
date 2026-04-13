use std::{
    ops::Deref,
    path::{Path, PathBuf},
    time::SystemTime,
};

use log::{debug, error};
use rand::{RngExt as _, distr::Alphanumeric, rngs::SmallRng};

use crate::{
    Never,
    deb_mirror::{self, Mirror},
    guards::InitBarrier,
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

/// A temporary file-path guard that automatically deletes the underlying file when dropped.
///
/// When `keep_on_drop` is set to `true`, the file is preserved on drop instead of being deleted.
/// This is used for partial download files that should survive failures for later resumption.
pub(crate) struct TempPath {
    path: Option<PathBuf>,
    keep_on_drop: bool,
}

impl TempPath {
    /// Create a new `TempPath` guard for an existing file.
    pub(crate) fn new(path: PathBuf, keep_on_drop: bool) -> Self {
        Self {
            path: Some(path),
            keep_on_drop,
        }
    }

    /// Defuse the temporary path guard, returning the underlying `PathBuf`.
    pub(crate) fn into_inner(mut self) -> PathBuf {
        std::mem::take(&mut self.path).expect("path has not been destructed yet")
    }

    /// Force deletion of the underlying file regardless of `keep_on_drop`.
    pub(crate) async fn remove(mut self) {
        if let Some(path) = self.path.take()
            && let Err(err) = tokio::fs::remove_file(&path).await
        {
            log::warn!("Failed to remove partial file `{}`:  {err}", path.display());
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

/// Compute a deterministic path for storing a partial download.
///
/// Returns `{cache_dir}/{mirror_cache_path}/tmp/{debname}.partial`.
/// Uses the mirror's own cache directory to avoid collisions between mirrors.
pub(crate) fn partial_path(cache_dir: &Path, mirror: &Mirror, debname: &str) -> PathBuf {
    let mirror_dir = deb_mirror::mirror_cache_path_impl(&mirror.host, mirror.port, &mirror.path);
    let filename = format!("{debname}.partial");
    let filename = Path::new(&filename);
    assert!(
        filename.is_relative(),
        "path construction must not contain absolute components"
    );
    [cache_dir, mirror_dir.as_path(), Path::new("tmp"), filename]
        .iter()
        .collect()
}

/// Open an existing partial file for writing at the end, returning the file, its current size,
/// the file's modification time, and a `TempPath` guard with `keep_on_drop: true`.
///
/// Uses `write(true)` + seek instead of `append(true)` so that splice(2) can use explicit
/// file offsets (`O_APPEND` is incompatible with splice's offset parameter).
///
/// By opening the file and querying size + mtime from the same file handle, this avoids
/// TOCTOU races between a separate `metadata()` check and a later `open()`.
pub(crate) async fn open_partial_file(
    path: &Path,
    _ibarrier: &InitBarrier<'_>, // ensures the file is opened while the init barrier is held
) -> Result<(tokio::fs::File, u64, SystemTime, TempPath), tokio::io::Error> {
    use tokio::io::AsyncSeekExt as _;

    let mut file = tokio::fs::File::options()
        .write(true)
        .read(true)
        .open(path)
        .await?;

    // Seek to the end so subsequent writes append correctly.
    let size = file.seek(std::io::SeekFrom::End(0)).await?;

    let mtime = file
        .metadata()
        .await?
        .modified()
        .expect("Platform should support modification timestamps via setup check");

    Ok((
        file,
        size,
        mtime,
        TempPath {
            path: Some(path.to_path_buf()),
            keep_on_drop: true,
        },
    ))
}

/// Create a new file at the given deterministic partial path, returning the file and a
/// `TempPath` guard with `keep_on_drop: true`.
pub(crate) async fn create_partial_file(
    path: &Path,
    mode: u32,
) -> Result<(tokio::fs::File, TempPath), tokio::io::Error> {
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }

    let file = tokio::fs::File::options()
        .create(true)
        .truncate(true)
        .write(true)
        .read(true)
        .mode(mode)
        .open(path)
        .await?;

    Ok((
        file,
        TempPath {
            path: Some(path.to_path_buf()),
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
    let metadata = match file.metadata().await {
        Ok(metadata) => metadata,
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
    if metadata.created().is_err() {
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
