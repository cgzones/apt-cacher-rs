use std::path::{Path, PathBuf};

use tracing::{debug, error, info, warn};
use xattr::FileExt as _;

use crate::{cache_layout::SUBDIR_TMP, global_config, utils::nofollow_options};

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

fn remove_dir_contents(path: &Path) -> Result<(), SetupError> {
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
    }
    Ok(())
}

pub(crate) fn task_setup() -> Result<(), SetupError> {
    let cache_path = &global_config().cache_directory;

    std::fs::create_dir_all(cache_path).map_err(SetupError::io("create directory", cache_path))?;

    // Check for creation and modification timestamp support
    let mdata =
        std::fs::metadata(cache_path).map_err(SetupError::io("inspect directory", cache_path))?;
    if !mdata.file_type().is_dir() {
        return Err(SetupError::NotADirectory(cache_path.clone()));
    }
    mdata.modified().map_err(SetupError::NoMtimeSupport)?;
    if let Err(err) = mdata.created() {
        info!(
            "No file creation timestamp (btime) support, volatile file caching is limited:  {err}"
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
            }
            Err(err) => {
                warn!("No extended file attribute support, ETags unavailable:  {err}");
            }
        }
    }

    let cache_tmp_path = cache_path.join(SUBDIR_TMP);

    std::fs::create_dir_all(&cache_tmp_path)
        .map_err(SetupError::io("create directory", &cache_tmp_path))?;

    remove_dir_contents(&cache_tmp_path)?;

    Ok(())
}
