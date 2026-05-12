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
pub(crate) fn remove_helper(file: &tokio::fs::File, display_path: &Path, key: &'static str) {
    if let Err(err) = tokio::task::block_in_place(|| XattrFile(file).remove_xattr(key)) {
        warn!(
            "Failed to remove invalid xattr from `{}` for key `{key}`:  {err}",
            display_path.display()
        );
    }
}

/// Marker returned by [`try_read_helper`] (and the typed wrappers in
/// [`crate::http_etag`] / [`crate::http_last_modified`]) when the xattr
/// syscall failed in a way that may succeed on retry — distinct from a
/// stable "no value" outcome (xattr absent, filesystem doesn't support
/// xattrs, or a malformed value was scrubbed).  Callers that don't need
/// the distinction can use the non-`try_` variants which collapse both
/// outcomes to `None`; callers that negative-cache (see
/// [`crate::cache_metadata`]) must use the `try_` variants and skip the
/// cache write on `Err`.
#[derive(Debug)]
pub(crate) struct XattrIoError;

/// Read the extended attribute value for the given key, distinguishing
/// transient I/O errors from a stable "no value" outcome.
///
/// - `Ok(Some(s))` — xattr present and decoded as UTF-8.
/// - `Ok(None)` — xattr absent, FS does not support xattrs, or the value
///   was malformed (invalid UTF-8) and has been scrubbed.  Safe to
///   negative-cache.
/// - `Err(XattrIoError)` — transient syscall failure (warning is logged
///   here).  Callers must NOT cache the absence; the next request may
///   succeed.
pub(crate) fn try_read_helper(
    file: &tokio::fs::File,
    display_path: &Path,
    key: &'static str,
) -> Result<Option<String>, XattrIoError> {
    let data = tokio::task::block_in_place(|| XattrFile(file).get_xattr(key));

    match data {
        Ok(None) => Ok(None),

        Ok(Some(val)) => match String::from_utf8(val) {
            Ok(s) => Ok(Some(s)),
            Err(err @ std::string::FromUtf8Error { .. }) => {
                warn!(
                    "Discarding invalid UTF-8 xattr from `{}` for key `{key}`:  {err}",
                    display_path.display()
                );

                remove_helper(file, display_path, key);

                Ok(None)
            }
        },

        Err(err) => {
            let kind = err.kind();
            if kind == std::io::ErrorKind::Unsupported
                || err.raw_os_error() == Some(Errno::ENODATA as i32)
            {
                Ok(None)
            } else {
                warn!(
                    "Unexpected error reading xattr from `{}` for key `{key}`:  {err}",
                    display_path.display()
                );
                Err(XattrIoError)
            }
        }
    }
}

/// Read the extended attribute value for the given key from the file.
///
/// Returns `None` on any error (graceful degradation).  Callers that
/// need to distinguish transient I/O errors from a stable "no value"
/// outcome (e.g. for negative caching) should use [`try_read_helper`].
#[must_use]
pub(crate) fn read_helper(
    file: &tokio::fs::File,
    display_path: &Path,
    key: &'static str,
) -> Option<String> {
    try_read_helper(file, display_path, key).ok().flatten()
}

/// Write the given value to the extended attribute for the given key on the file.
/// Logs warnings on failure but never propagates errors.
pub(crate) fn write_helper(
    file: &tokio::fs::File,
    display_path: &Path,
    key: &'static str,
    value: &[u8],
) {
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
