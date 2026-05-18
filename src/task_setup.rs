use std::os::unix::fs::OpenOptionsExt as _;

use anyhow::Context as _;
use log::{debug, error, info, warn};
use xattr::FileExt as _;

use crate::{cache_layout::SUBDIR_TMP, global_config};

fn remove_dir_contents<P: AsRef<std::path::Path>>(path: P) -> anyhow::Result<()> {
    for entry in std::fs::read_dir(path)? {
        let entry_path = entry?.path();
        let file_type = std::fs::symlink_metadata(&entry_path)
            .with_context(|| format!("Failed to stat entry `{}`", entry_path.display()))?
            .file_type();

        if file_type.is_dir() {
            debug!("Removing directory `{}`", entry_path.display());
            std::fs::remove_dir_all(&entry_path).with_context(|| {
                format!("Failed to remove directory `{}`", entry_path.display())
            })?;
        } else if file_type.is_symlink() {
            debug!("Removing symlink `{}`", entry_path.display());
            std::fs::remove_file(&entry_path)
                .with_context(|| format!("Failed to remove symlink `{}`", entry_path.display()))?;
        } else {
            debug!("Removing file `{}`", entry_path.display());
            std::fs::remove_file(&entry_path)
                .with_context(|| format!("Failed to remove file `{}`", entry_path.display()))?;
        }
    }
    Ok(())
}

pub(crate) fn task_setup() -> anyhow::Result<()> {
    let cache_path = &global_config().cache_directory;

    std::fs::create_dir_all(cache_path)
        .with_context(|| format!("Failed to create directory `{}`", cache_path.display()))?;

    // Check for creation and modification timestamp support
    let mdata = std::fs::metadata(cache_path)
        .with_context(|| format!("Failed to inspect directory `{}`", cache_path.display()))?;
    if !mdata.file_type().is_dir() {
        anyhow::bail!(
            "Cache directory `{}` is not a directory",
            cache_path.display()
        );
    }
    mdata
        .modified()
        .context("No file modification timestamp (mtime) support")?;
    if let Err(err) = mdata.created() {
        info!(
            "No file creation timestamp (btime) support, volatile file caching is limited:  {err}"
        );
    }

    // Check for extended attribute support
    {
        const ETAG_PROBE: &str = "user.etag_probe";
        const ETAG_PROBE_VALUE: &[u8] = b"probe";

        let etag_probe_path = cache_path.join(".etag_probe");

        let etag_probe_file = std::fs::File::options()
            .write(true)
            .create(true)
            .custom_flags(nix::libc::O_NOFOLLOW)
            .open(&etag_probe_path)
            .with_context(|| {
                format!(
                    "Failed to create extended attribute probe file `{}`",
                    etag_probe_path.display()
                )
            })?;

        let etag_result = etag_probe_file
            .set_xattr(ETAG_PROBE, ETAG_PROBE_VALUE)
            .and_then(|()| etag_probe_file.get_xattr(ETAG_PROBE))
            .and_then(|val| etag_probe_file.remove_xattr(ETAG_PROBE).map(|()| val));
        drop(etag_probe_file);
        if let Err(err) = std::fs::remove_file(&etag_probe_path) {
            error!(
                "Failed to remove extended attribute probe file `{}`:  {err}",
                etag_probe_path.display()
            );
        }
        match etag_result {
            Ok(val) if val.as_deref() == Some(ETAG_PROBE_VALUE) => {
                debug!("Extended attribute support verified, ETags available");
            }
            Ok(val) => {
                warn!(
                    "Extended attribute support test failed on `{}`: got {val:?}, expected `probe`",
                    etag_probe_path.display()
                );
            }
            Err(err) => {
                warn!("No extended file attribute support, ETags unavailable:  {err}");
            }
        }
    }

    let cache_tmp_path = cache_path.join(SUBDIR_TMP);

    std::fs::create_dir_all(&cache_tmp_path)
        .with_context(|| format!("Failed to create directory `{}`", cache_tmp_path.display()))?;

    remove_dir_contents(&cache_tmp_path).with_context(|| {
        format!(
            "Failed to empty out temporary directory `{}`",
            cache_tmp_path.display()
        )
    })?;

    Ok(())
}
