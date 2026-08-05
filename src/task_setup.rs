use std::io::Write as _;
use std::path::{Path, PathBuf};

use nix::errno::Errno;
use nix::fcntl::{Flock, FlockArg};
use tracing::{debug, error, info, warn};
use xattr::FileExt as _;

use crate::{
    cache_layout::SUBDIR_TMP, global_config, utils::nofollow_options,
    xattr_helpers::set_xattr_supported,
};

/// Failure while preparing the cache directory at startup.
///
/// `Display` renders this error only; the underlying cause hangs off
/// [`std::error::Error::source`], so log it via [`crate::error::ErrorReport`].
#[derive(Debug, thiserror::Error)]
pub(crate) enum SetupError {
    #[error("Failed to {action} `{}`", path.display())]
    Io {
        action: &'static str,
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("Cache directory `{}` is not a directory", .0.display())]
    NotADirectory(PathBuf),
    #[error("No file modification timestamp (mtime) support")]
    NoMtimeSupport(#[source] std::io::Error),
    #[error(
        "Cache directory `{}` is already in use by another apt-cacher-rs instance{holder}",
        path.display()
    )]
    LockInUse { path: PathBuf, holder: String },
}

impl SetupError {
    fn io(action: &'static str, path: &Path) -> impl FnOnce(std::io::Error) -> Self {
        move |source| Self::Io {
            action,
            path: path.to_path_buf(),
            source,
        }
    }
}

/// Name of the instance lock file at the cache-directory root. Unlike the
/// healthcheck probe it persists for the process lifetime, so the cache
/// scan skips it alongside `healthcheck::PROBE_FILENAME`.
pub(crate) const LOCK_FILENAME: &str = ".apt-cacher-rs.lock";

/// Take an exclusive advisory `flock(2)` on the cache-directory lock file,
/// refusing startup when another instance holds it: a second instance
/// sharing the cache would purge `tmp/` under live downloads, double-count
/// the quota, and run cleanup against files the other is serving.
fn lock_cache_dir(cache_path: &Path) -> Result<Flock<std::fs::File>, SetupError> {
    let lock_path = cache_path.join(LOCK_FILENAME);
    // `.create(true)` so the lock file from a previous run is reused.
    let file = nofollow_options()
        .read(true)
        .write(true)
        .create(true)
        .open(&lock_path)
        .map_err(SetupError::io("open lock file", &lock_path))?;
    match Flock::lock(file, FlockArg::LockExclusiveNonblock) {
        Ok(lock) => {
            // Best-effort PID stamp for operator diagnostics.
            let stamp = lock
                .set_len(0)
                .and_then(|()| writeln!(&*lock, "{}", std::process::id()));
            if let Err(err) = stamp {
                debug!(
                    "Failed to stamp lock file `{}`:  {err}",
                    lock_path.display()
                );
            }
            Ok(lock)
        }
        Err((mut file, errno)) if errno == Errno::EWOULDBLOCK => {
            use std::io::Read as _;
            let mut buf = [0u8; 32];
            let holder = file
                .read(&mut buf)
                .ok()
                .and_then(|n| std::str::from_utf8(&buf[..n]).ok())
                .and_then(|content| content.trim().parse::<u32>().ok())
                .map_or_else(String::new, |pid| format!(" (process {pid})"));
            Err(SetupError::LockInUse {
                path: cache_path.to_path_buf(),
                holder,
            })
        }
        Err((_file, errno)) => Err(SetupError::io("lock", &lock_path)(errno.into())),
    }
}

/// Returns the number of removed entries.
fn remove_dir_contents(path: &Path) -> Result<usize, SetupError> {
    let mut removed = 0usize;
    for entry in std::fs::read_dir(path).map_err(SetupError::io("read directory", path))? {
        let entry_path = entry
            .map_err(SetupError::io("read directory", path))?
            .path();
        let file_type = std::fs::symlink_metadata(&entry_path)
            .map_err(SetupError::io("stat entry", &entry_path))?
            .file_type();

        if file_type.is_dir() {
            debug!("Removing directory `{}`", entry_path.display());
            std::fs::remove_dir_all(&entry_path)
                .map_err(SetupError::io("remove directory", &entry_path))?;
        } else if file_type.is_symlink() {
            debug!("Removing symlink `{}`", entry_path.display());
            std::fs::remove_file(&entry_path)
                .map_err(SetupError::io("remove symlink", &entry_path))?;
        } else {
            debug!("Removing file `{}`", entry_path.display());
            std::fs::remove_file(&entry_path)
                .map_err(SetupError::io("remove file", &entry_path))?;
        }
        removed = removed.saturating_add(1);
    }
    Ok(removed)
}

pub(crate) fn task_setup() -> Result<Flock<std::fs::File>, SetupError> {
    let cache_path = &global_config().cache_directory;

    std::fs::create_dir_all(cache_path).map_err(SetupError::io("create directory", cache_path))?;

    // Check for creation and modification timestamp support
    let mdata =
        std::fs::metadata(cache_path).map_err(SetupError::io("inspect directory", cache_path))?;
    if !mdata.file_type().is_dir() {
        return Err(SetupError::NotADirectory(cache_path.clone()));
    }

    // Locked before anything below mutates the cache (the xattr probe write,
    // the `tmp/` purge — destructive to a live instance's partial downloads).
    let cache_lock = lock_cache_dir(cache_path)?;
    mdata.modified().map_err(SetupError::NoMtimeSupport)?;
    if let Err(err) = mdata.created() {
        warn!(
            "No file creation timestamp (btime) support on `{}`; volatile index files cannot have their freshness window refreshed and are revalidated upstream more often:  {err}",
            cache_path.display()
        );
    }

    // Check for extended attribute support
    {
        // Probe the same namespace the runtime uses (`user.apt_cacher_rs.*` —
        // see `xattr_helpers.rs`, `http_etag.rs`, `http_last_modified.rs`) so a
        // filesystem or LSM policy that allows the generic `user.*` namespace
        // but restricts custom prefixes does not pass the probe while still
        // blocking real reads/writes at runtime.
        const XATTR_PROBE: &str = "user.apt_cacher_rs.probe";
        const XATTR_PROBE_VALUE: &[u8] = b"probe";

        let xattr_probe_path = cache_path.join(".xattr_probe");

        let xattr_probe_file = nofollow_options()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&xattr_probe_path)
            .map_err(SetupError::io(
                "create extended attribute probe file",
                &xattr_probe_path,
            ))?;

        let xattr_result = xattr_probe_file
            .set_xattr(XATTR_PROBE, XATTR_PROBE_VALUE)
            .and_then(|()| xattr_probe_file.get_xattr(XATTR_PROBE))
            .and_then(|val| xattr_probe_file.remove_xattr(XATTR_PROBE).map(|()| val));
        drop(xattr_probe_file);
        if let Err(err) = std::fs::remove_file(&xattr_probe_path) {
            error!(
                "Failed to remove extended attribute probe file `{}`:  {err}",
                xattr_probe_path.display()
            );
        }
        match xattr_result {
            Ok(val) if val.as_deref() == Some(XATTR_PROBE_VALUE) => {
                debug!("Extended attribute support verified, ETags available");
            }
            Ok(val) => {
                warn!(
                    "Extended attribute support test failed on `{}`: got {val:?}, expected `probe`",
                    xattr_probe_path.display()
                );
                set_xattr_supported(false);
            }
            Err(err) => {
                warn!(
                    "No extended file attribute support on `{}`; ETag/Last-Modified revalidation and cleanup checksum memoization are disabled - mount the cache filesystem with user_xattr support:  {err}",
                    cache_path.display()
                );
                set_xattr_supported(false);
            }
        }
    }

    let cache_tmp_path = cache_path.join(SUBDIR_TMP);

    std::fs::create_dir_all(&cache_tmp_path)
        .map_err(SetupError::io("create directory", &cache_tmp_path))?;

    // Leftovers here are partial downloads from a previous run that never
    // committed; a non-empty purge is the one startup-visible trace of an
    // unclean shutdown.
    let purged = remove_dir_contents(&cache_tmp_path)?;
    if purged > 0 {
        info!(
            "Purged {purged} leftover entries from `{}`",
            cache_tmp_path.display()
        );
    }

    Ok(cache_lock)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cache_dir_lock_excludes_second_instance() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let first = lock_cache_dir(tmp.path()).expect("first lock");
        let err = lock_cache_dir(tmp.path()).expect_err("second lock must fail");
        assert!(
            err.to_string().contains("already in use"),
            "unexpected error: {err}"
        );
        drop(first);
        let _relock = lock_cache_dir(tmp.path()).expect("relock after release");
    }

    #[test]
    fn cache_dir_lock_stamps_pid() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let _lock = lock_cache_dir(tmp.path()).expect("lock");
        let content = std::fs::read_to_string(tmp.path().join(LOCK_FILENAME)).expect("read");
        assert_eq!(content.trim().parse::<u32>().ok(), Some(std::process::id()));
    }
}
