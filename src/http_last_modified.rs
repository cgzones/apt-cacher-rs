use std::path::Path;

use log::warn;

use crate::{http_range::HttpDate, xattr_helpers};

/// The extended attribute name used to store upstream `Last-Modified` values.
const XATTR_LAST_MODIFIED: &str = "user.apt_cacher_rs.last_modified";

/// Validate that a string is a parseable HTTP-date per RFC 9110 §5.6.7.
#[must_use]
fn is_valid_http_date(s: &str) -> bool {
    HttpDate::parse(s).is_some()
}

/// Read a `Last-Modified` value from the file's extended attributes,
/// distinguishing transient I/O errors from a stable "no value" outcome.
///
/// See [`xattr_helpers::try_read_helper`] for the semantics; a stored
/// value that fails to parse as an HTTP-date is scrubbed and reported
/// as `Ok(None)`.
pub(crate) fn try_read_last_modified(
    file: &tokio::fs::File,
    display_path: &Path,
) -> Result<Option<(String, HttpDate)>, xattr_helpers::XattrIoError> {
    let Some(data) = xattr_helpers::try_read_helper(file, display_path, XATTR_LAST_MODIFIED)?
    else {
        return Ok(None);
    };

    let Some(time) = HttpDate::parse(&data) else {
        warn!(
            "Discarding malformed Last-Modified from `{}`: {}",
            display_path.display(),
            data.escape_debug()
        );

        xattr_helpers::remove_helper(file, display_path, XATTR_LAST_MODIFIED);

        return Ok(None);
    };

    Ok(Some((data, time)))
}

/// Write a `Last-Modified` value to the file's extended attributes.
///
/// Malformed values are skipped. Logs warnings on failure but never propagates errors.
pub(crate) fn write_last_modified(file: &tokio::fs::File, display_path: &Path, value: &str) {
    if !is_valid_http_date(value) {
        warn!(
            "Skipping write of malformed Last-Modified to `{}`: {}",
            display_path.display(),
            value.escape_debug()
        );
        return;
    }

    xattr_helpers::write_helper(file, display_path, XATTR_LAST_MODIFIED, value.as_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_valid_http_date_test() {
        assert!(is_valid_http_date("Thu, 01 Jan 1970 00:00:00 GMT"));
        assert!(is_valid_http_date("Tue, 21 Mar 2361 19:15:09 GMT"));

        assert!(!is_valid_http_date(""));
        assert!(!is_valid_http_date("not a date"));
        assert!(!is_valid_http_date("Thu, 32 Jan 1970 00:00:00 GMT"));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn write_then_read_last_modified() {
        let dir = tempfile::tempdir().expect("create tempdir");
        let path = dir.path().join("probe");
        let file = tokio::fs::File::create(&path).await.expect("create file");

        let value = "Tue, 21 Mar 2361 19:15:09 GMT";
        write_last_modified(&file, &path, value);

        // Skip the round-trip assertion when xattrs aren't supported on the test FS.
        if let Ok(Some((got_str, got_time))) = try_read_last_modified(&file, &path) {
            assert_eq!(got_str, value);
            assert_eq!(got_time, HttpDate::from_secs(12_345_678_909));
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn write_skips_malformed() {
        let dir = tempfile::tempdir().expect("create tempdir");
        let path = dir.path().join("probe");
        let file = tokio::fs::File::create(&path).await.expect("create file");

        write_last_modified(&file, &path, "garbage");
        assert!(matches!(try_read_last_modified(&file, &path), Ok(None)));
    }
}
