//! Extended-attribute helpers.
//!
//! # Runtime requirement
//!
//! The read/write/remove helpers use [`tokio::task::block_in_place`] to run
//! the synchronous `xattr` calls without blocking the reactor.  This requires
//! a multi-threaded Tokio runtime — calling these helpers from a
//! `current_thread` runtime (including `#[tokio::test]` without
//! `flavor = "multi_thread"`) will **panic**.

use std::{num::ParseIntError, path::Path};

use log::warn;
use nix::errno::Errno;
use xattr::FileExt as _;

/// Wrapper to implement [`xattr::FileExt`] for [`tokio::fs::File`].
pub(crate) struct XattrFile<'a>(pub(crate) &'a tokio::fs::File);

impl std::os::fd::AsRawFd for XattrFile<'_> {
    #[inline]
    fn as_raw_fd(&self) -> std::os::fd::RawFd {
        self.0.as_raw_fd()
    }
}

impl xattr::FileExt for XattrFile<'_> {}

/// Remove the extended attribute for the given key from the file.
/// Logs warnings on failure but never propagates errors.
pub(crate) fn remove_helper(file: &tokio::fs::File, display_path: &Path, key: &str) {
    if let Err(err) = tokio::task::block_in_place(|| XattrFile(file).remove_xattr(key)) {
        warn!(
            "Failed to remove invalid xattr from `{}` for key `{key}`:  {err}",
            display_path.display()
        );
    }
}

/// Read the extended attribute value for the given key from the file.
///
/// Returns `None` on any error (graceful degradation).
#[must_use]
pub(crate) fn read_helper(
    file: &tokio::fs::File,
    display_path: &Path,
    key: &str,
) -> Option<String> {
    let data = tokio::task::block_in_place(|| XattrFile(file).get_xattr(key));

    match data {
        Ok(None) => None,

        Ok(Some(val)) => {
            let s = match String::from_utf8(val) {
                Ok(s) => s,
                Err(err @ std::string::FromUtf8Error { .. }) => {
                    warn!(
                        "Discarding invalid UTF-8 xattr from `{}` for key `{key}`:  {err}",
                        display_path.display()
                    );

                    remove_helper(file, display_path, key);

                    return None;
                }
            };

            Some(s)
        }

        Err(err) => {
            let kind = err.kind();
            if kind != std::io::ErrorKind::Unsupported
                && err.raw_os_error() != Some(Errno::ENODATA as i32)
            {
                warn!(
                    "Unexpected error reading xattr from `{}` for key `{key}`:  {err}",
                    display_path.display()
                );
            }
            None
        }
    }
}

/// Write the given value to the extended attribute for the given key on the file.
/// Logs warnings on failure but never propagates errors.
pub(crate) fn write_helper(file: &tokio::fs::File, display_path: &Path, key: &str, value: &[u8]) {
    let data = tokio::task::block_in_place(|| XattrFile(file).set_xattr(key, value));

    if let Err(err) = data {
        let kind = err.kind();
        if kind != std::io::ErrorKind::Unsupported {
            warn!(
                "Failed to write xattr to `{}` for key `{key}`:  {err}",
                display_path.display()
            );
        }
    }
}

/// The extended attribute name used to store the expected total file size on partial downloads.
const XATTR_EXPECTED_SIZE: &str = "user.apt_cacher_rs.expected_size";

/// Read the expected total file size from a partial file's extended attributes.
///
/// Returns `None` on any error (graceful degradation).
#[must_use]
pub(crate) fn read_expected_size(file: &tokio::fs::File, display_path: &Path) -> Option<u64> {
    let data = read_helper(file, display_path, XATTR_EXPECTED_SIZE)?;

    match data.parse::<u64>() {
        Ok(size) => Some(size),
        Err(_err @ ParseIntError { .. }) => {
            warn!(
                "Discarding malformed expected_size xattr from `{}`: {}",
                display_path.display(),
                data.escape_debug()
            );

            remove_helper(file, display_path, XATTR_EXPECTED_SIZE);

            None
        }
    }
}

/// Write the expected total file size to a partial file's extended attributes.
pub(crate) fn write_expected_size(file: &tokio::fs::File, display_path: &Path, size: u64) {
    write_helper(
        file,
        display_path,
        XATTR_EXPECTED_SIZE,
        size.to_string().as_bytes(),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn write_then_read_expected_size() {
        let dir = tempfile::tempdir().expect("create tempdir");
        let path = dir.path().join("probe");
        let file = tokio::fs::File::create(&path).await.expect("create file");

        write_expected_size(&file, &path, 1_071_434_820);

        // Skip the round-trip assertion when xattrs aren't supported on the test FS.
        if let Some(size) = read_expected_size(&file, &path) {
            assert_eq!(size, 1_071_434_820);
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn read_expected_size_missing() {
        let dir = tempfile::tempdir().expect("create tempdir");
        let path = dir.path().join("probe");
        let file = tokio::fs::File::create(&path).await.expect("create file");

        assert_eq!(read_expected_size(&file, &path), None);
    }
}
