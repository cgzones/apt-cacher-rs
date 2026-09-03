//! Extended-attribute helpers: one typed layer over every
//! `user.apt_cacher_rs.*` attribute the daemon persists.
//!
//! A persisted attribute is a type implementing [`XattrValue`] (`ETag`,
//! `LastModified`, [`ExpectedSize`], [`crate::verified_marker::CleanupMarker`]); the generic
//! [`try_read`] / [`read`] / [`write()`] / [`remove`] helpers own the whole
//! degradation policy once - the `XATTR_SUPPORTED` short-circuit, the
//! absent/unsupported/`ENODATA` collapse to `None`, the malformed-value scrub
//! and its once-gated warn, and the transient-failure warn - so a new
//! attribute is a type, not a module plus three call sites. The `xattr`
//! crate already does a single-syscall fast path per read; the hot cost of
//! an attribute is its value, which `cache_metadata` caches.
//!
//! # Runtime requirement
//!
//! The [`XattrTarget`] impl for [`tokio::fs::File`] runs every syscall
//! through [`tokio::task::block_in_place`], which requires a multi-threaded
//! Tokio runtime - calling the helpers on a tokio file from a
//! `current_thread` runtime (including `#[tokio::test]` without
//! `flavor = "multi_thread"`) will **panic**. The [`std::fs::File`] impl
//! issues the syscall directly and is for callers already on a blocking
//! thread (cleanup's digest verification and `integrity::verify_temp_file`);
//! so does [`XattrFile`], which wraps a tokio file for a caller that has
//! entered `block_in_place` itself to batch several operations.

use std::{
    borrow::Cow,
    io,
    num::ParseIntError,
    path::Path,
    sync::atomic::{AtomicBool, Ordering},
};

use nix::libc;
use tracing::warn;
use xattr::FileExt as _;

use crate::{error::ErrorReport, log_once::warn_once_or_info_gated, warn_once_or_debug};

/// Wrapper to implement [`xattr::FileExt`] for [`tokio::fs::File`].
///
/// As an [`XattrTarget`] it issues the syscall *directly*, unlike the
/// [`tokio::fs::File`] impl: it is for a caller that has already entered one
/// [`tokio::task::block_in_place`] section around several attribute
/// operations on the same file (see
/// `cache_metadata::write_upstream_metadata`), so the download path pays one
/// worker demotion instead of one per attribute.
pub(crate) struct XattrFile<'a>(pub(crate) &'a tokio::fs::File);

impl std::os::fd::AsRawFd for XattrFile<'_> {
    #[inline]
    fn as_raw_fd(&self) -> std::os::fd::RawFd {
        self.0.as_raw_fd()
    }
}

impl xattr::FileExt for XattrFile<'_> {}

/// An open file the helpers address by descriptor. The impls differ only in
/// how the blocking syscall reaches the kernel (see the module doc's
/// runtime requirement).
pub(crate) trait XattrTarget {
    fn get(&self, key: &'static str) -> io::Result<Option<Vec<u8>>>;
    fn set(&self, key: &'static str, value: &[u8]) -> io::Result<()>;
    fn remove(&self, key: &'static str) -> io::Result<()>;
}

impl XattrTarget for tokio::fs::File {
    fn get(&self, key: &'static str) -> io::Result<Option<Vec<u8>>> {
        tokio::task::block_in_place(|| XattrFile(self).get_xattr(key))
    }

    fn set(&self, key: &'static str, value: &[u8]) -> io::Result<()> {
        tokio::task::block_in_place(|| XattrFile(self).set_xattr(key, value))
    }

    fn remove(&self, key: &'static str) -> io::Result<()> {
        tokio::task::block_in_place(|| XattrFile(self).remove_xattr(key))
    }
}

impl XattrTarget for XattrFile<'_> {
    fn get(&self, key: &'static str) -> io::Result<Option<Vec<u8>>> {
        self.get_xattr(key)
    }

    fn set(&self, key: &'static str, value: &[u8]) -> io::Result<()> {
        self.set_xattr(key, value)
    }

    fn remove(&self, key: &'static str) -> io::Result<()> {
        self.remove_xattr(key)
    }
}

impl XattrTarget for std::fs::File {
    fn get(&self, key: &'static str) -> io::Result<Option<Vec<u8>>> {
        self.get_xattr(key)
    }

    fn set(&self, key: &'static str, value: &[u8]) -> io::Result<()> {
        self.set_xattr(key, value)
    }

    fn remove(&self, key: &'static str) -> io::Result<()> {
        self.remove_xattr(key)
    }
}

/// A value persisted as one `user.apt_cacher_rs.*` extended attribute.
///
/// A type implementing this is valid by construction (its only constructors
/// are [`Self::parse`] and validating `new`s), so [`write()`] never has to
/// validate; [`try_read`] scrubs a stored value [`Self::parse`] rejects.
pub(crate) trait XattrValue: Sized {
    /// Full attribute name, `user.apt_cacher_rs.<name>`.
    const KEY: &'static str;
    /// Human name for log lines (`ETag`, `Last-Modified`, `expected_size`).
    const LABEL: &'static str;
    /// Consequence clause of the write-failure warn: what the daemon loses
    /// when this value does not stick.
    const WRITE_FAILURE_CONSEQUENCE: &'static str;

    /// Once-gate of this value's malformed-discard warn. A `static` inside
    /// the generic [`try_read`] would be one gate shared by every value type
    /// (a `static` item is not monomorphised), so each type owns its own.
    fn discard_gate() -> &'static AtomicBool;

    /// Decode a stored value; `None` means malformed (it is scrubbed).
    fn parse(raw: &str) -> Option<Self>;

    /// Encode for storage. Every value is text, so a malformed stored value
    /// (including invalid UTF-8) is rendered `escape_debug` in the discard warn.
    fn render(&self) -> Cow<'_, str>;
}

/// Whether the cache filesystem supports the `user.apt_cacher_rs.*`
/// namespace, recorded once by `task_setup`'s startup probe. Every helper
/// short-circuits when it is false (no syscall, no log line), and cleanup
/// announces once per cycle that digest-verification memoization cannot
/// stick.
static XATTR_SUPPORTED: AtomicBool = AtomicBool::new(true);

pub(crate) fn set_xattr_supported(supported: bool) {
    XATTR_SUPPORTED.store(supported, Ordering::Relaxed);
}

pub(crate) fn xattr_supported() -> bool {
    XATTR_SUPPORTED.load(Ordering::Relaxed)
}

/// Marker returned by [`try_read`] when the xattr syscall failed in a way
/// that may succeed on retry - distinct from a stable "no value" outcome
/// (xattr absent, filesystem doesn't support xattrs, or a malformed value
/// was scrubbed). Callers that don't need the distinction use [`read`],
/// which collapses both outcomes to `None`; callers that negative-cache
/// (see [`crate::cache_metadata`]) must use [`try_read`] and skip the cache
/// write on `Err`.
#[derive(Debug)]
pub(crate) struct XattrIoError;

/// Remove `V`'s attribute from the file. Logs on failure but never
/// propagates errors: the only caller is the malformed-value scrub, whose
/// failure leaves the invalid value in place for the next read to discard
/// again.
pub(crate) fn remove<V: XattrValue>(file: &impl XattrTarget, display_path: &Path) {
    if !xattr_supported() {
        return;
    }
    if let Err(err) = file.remove(V::KEY)
        && err.kind() != io::ErrorKind::Unsupported
    {
        warn!(
            "Failed to remove invalid xattr from `{}` for key `{}`; the invalid value stays on the file:  {}",
            display_path.display(),
            V::KEY,
            ErrorReport(&err)
        );
    }
}

/// Read `V` from the file, distinguishing transient I/O errors from a
/// stable "no value" outcome.
///
/// - `Ok(Some(v))` - xattr present and parsed.
/// - `Ok(None)` - xattr absent, FS does not support xattrs, or the value
///   was malformed (invalid UTF-8 or rejected by [`XattrValue::parse`]) and
///   has been scrubbed. Safe to negative-cache.
/// - `Err(XattrIoError)` - transient syscall failure (warning is logged
///   here). Callers must NOT cache the absence; the next read may succeed.
pub(crate) fn try_read<V: XattrValue>(
    file: &impl XattrTarget,
    display_path: &Path,
) -> Result<Option<V>, XattrIoError> {
    if !xattr_supported() {
        return Ok(None);
    }

    let raw = match file.get(V::KEY) {
        Ok(None) => return Ok(None),
        Ok(Some(raw)) => raw,
        Err(err) => {
            if err.kind() == io::ErrorKind::Unsupported || err.raw_os_error() == Some(libc::ENODATA)
            {
                return Ok(None);
            }
            // ENOTSUP/ENODATA are filtered above, so what reaches here is
            // the persistent failure class (LSM denial, EIO) on a
            // per-request path: warn once, then degrade.
            warn_once_or_debug!(
                "Failed to read xattr from `{}` for key `{}`; treating the value as absent for this read:  {}",
                display_path.display(),
                V::KEY,
                ErrorReport(&err)
            );
            return Err(XattrIoError);
        }
    };

    let parsed = std::str::from_utf8(&raw).ok().and_then(V::parse);
    let Some(value) = parsed else {
        // Reachable per request for any cached file whose xattr is
        // malformed, and nothing rewrites the value, so once-gated.
        warn_once_or_info_gated(
            V::discard_gate(),
            format_args!(
                "Discarding malformed {} from `{}`: `{}`",
                V::LABEL,
                display_path.display(),
                String::from_utf8_lossy(&raw).escape_debug()
            ),
        );
        remove::<V>(file, display_path);
        return Ok(None);
    };
    Ok(Some(value))
}

/// Read `V` from the file, `None` on any error (graceful degradation).
/// Callers that need to distinguish transient I/O errors from a stable
/// "no value" outcome (e.g. for negative caching) use [`try_read`].
#[must_use]
pub(crate) fn read<V: XattrValue>(file: &impl XattrTarget, display_path: &Path) -> Option<V> {
    try_read::<V>(file, display_path).ok().flatten()
}

/// Persist `value` on the file. Logs on failure but never propagates
/// errors; `ErrorKind::Unsupported` is silent (the startup probe already
/// warned once for the filesystem).
pub(crate) fn write<V: XattrValue>(file: &impl XattrTarget, display_path: &Path, value: &V) {
    if !xattr_supported() {
        return;
    }
    if let Err(err) = file.set(V::KEY, value.render().as_bytes())
        && err.kind() != io::ErrorKind::Unsupported
    {
        warn_once_or_debug!(
            "Failed to write xattr to `{}` for key `{}`; {}:  {}",
            display_path.display(),
            V::KEY,
            V::WRITE_FAILURE_CONSEQUENCE,
            ErrorReport(&err)
        );
    }
}

/// The expected total size of a partial download, so a resume can detect
/// an upstream file that changed underneath it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ExpectedSize(pub(crate) u64);

impl XattrValue for ExpectedSize {
    const KEY: &'static str = "user.apt_cacher_rs.expected_size";
    const LABEL: &'static str = "expected_size";
    const WRITE_FAILURE_CONSEQUENCE: &'static str =
        "a resume of this partial download cannot detect an upstream size change";

    fn discard_gate() -> &'static AtomicBool {
        static GATE: AtomicBool = AtomicBool::new(false);
        &GATE
    }

    fn parse(raw: &str) -> Option<Self> {
        match raw.parse::<u64>() {
            Ok(size) => Some(Self(size)),
            Err(_err @ ParseIntError { .. }) => None,
        }
    }

    fn render(&self) -> Cow<'_, str> {
        Cow::Owned(self.0.to_string())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Plant a raw (possibly malformed) value under `V`'s key, bypassing the
    /// typed layer. `false` when the test filesystem rejects user xattrs, so
    /// the caller skips its assertions instead of failing on tmpfs without
    /// `user_xattr`.
    pub(crate) fn plant_raw<V: XattrValue>(file: &std::fs::File, raw: &[u8]) -> bool {
        match file.set_xattr(V::KEY, raw) {
            Ok(()) => true,
            Err(err) => {
                assert_eq!(
                    err.kind(),
                    io::ErrorKind::Unsupported,
                    "unexpected xattr failure: {err}"
                );
                false
            }
        }
    }

    /// Whether `V`'s key is present on the file, read raw.
    pub(crate) fn raw_present<V: XattrValue>(file: &std::fs::File) -> bool {
        matches!(file.get_xattr(V::KEY), Ok(Some(_)))
    }

    /// The scrub-on-malformed contract every value type inherits: a stored
    /// value `parse` rejects reads back as `Ok(None)` and is gone afterwards,
    /// while a well-formed one round-trips through `render`.
    pub(crate) fn assert_scrubs_malformed_and_round_trips<
        V: XattrValue + PartialEq + std::fmt::Debug,
    >(
        malformed: &[u8],
        valid: &V,
    ) {
        let dir = tempfile::tempdir().expect("create tempdir");
        let path = dir.path().join("probe");
        let file = std::fs::File::create(&path).expect("create file");

        if !plant_raw::<V>(&file, malformed) {
            return;
        }
        assert!(matches!(try_read::<V>(&file, &path), Ok(None)));
        assert!(!raw_present::<V>(&file), "malformed value is scrubbed");

        write(&file, &path, valid);
        assert_eq!(read::<V>(&file, &path).as_ref(), Some(valid));

        remove::<V>(&file, &path);
        assert!(matches!(try_read::<V>(&file, &path), Ok(None)));
    }

    #[test]
    fn expected_size_parse_and_render() {
        assert_eq!(
            ExpectedSize::parse("1071434820"),
            Some(ExpectedSize(1_071_434_820))
        );
        assert_eq!(ExpectedSize::parse("0"), Some(ExpectedSize(0)));
        assert_eq!(ExpectedSize::parse(""), None);
        assert_eq!(ExpectedSize::parse("-1"), None);
        assert_eq!(ExpectedSize::parse("12 "), None);
        assert_eq!(ExpectedSize::parse("18446744073709551616"), None);
        assert_eq!(ExpectedSize(42).render(), "42");
    }

    #[test]
    fn expected_size_scrubs_malformed_and_round_trips() {
        assert_scrubs_malformed_and_round_trips(b"lots", &ExpectedSize(1_071_434_820));
        assert_scrubs_malformed_and_round_trips(b"\xff\xfe", &ExpectedSize(7));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn write_then_read_expected_size_on_tokio_file() {
        let dir = tempfile::tempdir().expect("create tempdir");
        let path = dir.path().join("probe");
        let file = tokio::fs::File::create(&path).await.expect("create file");

        write(&file, &path, &ExpectedSize(1_071_434_820));

        // Skip the round-trip assertion when xattrs aren't supported on the test FS.
        if let Some(size) = read::<ExpectedSize>(&file, &path) {
            assert_eq!(size, ExpectedSize(1_071_434_820));
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn read_expected_size_missing() {
        let dir = tempfile::tempdir().expect("create tempdir");
        let path = dir.path().join("probe");
        let file = tokio::fs::File::create(&path).await.expect("create file");

        assert_eq!(read::<ExpectedSize>(&file, &path), None);
    }
}
