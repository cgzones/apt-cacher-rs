//! `Content-Type` for a cached file, derived from its debname, and the
//! once-per-value warning when upstream announces a different type.

use crate::{deb_mirror, warn_once_or_info};

/// Warn (once) if the upstream `Content-Type` differs from the type derived
/// from the cached file's basename. The non-standard `binary/octet-stream`
/// is widely advertised by Debian mirrors and is treated as a no-op rather
/// than a mismatch to keep the log quiet.
pub(crate) fn warn_on_content_type_mismatch(
    upstream: Option<&str>,
    mirror: &deb_mirror::Mirror,
    debname: &str,
) {
    let Some(upstream_ct) = upstream else {
        return;
    };
    if upstream_ct.eq_ignore_ascii_case("binary/octet-stream") {
        return;
    }

    let expected = content_type_for_cached_file(debname);
    if upstream_ct.eq_ignore_ascii_case(expected) {
        return;
    }
    // `application/x-deb` is the legacy unregistered alias for the
    // IANA-registered `application/vnd.debian.binary-package`; treat them
    // as equivalent.
    if expected == "application/vnd.debian.binary-package"
        && upstream_ct.eq_ignore_ascii_case("application/x-deb")
    {
        return;
    }
    // `application/x-gzip` is the legacy non-standard alias for the
    // IANA-registered `application/gzip` (RFC 6713); treat them as equivalent.
    if expected == "application/gzip" && upstream_ct.eq_ignore_ascii_case("application/x-gzip") {
        return;
    }
    warn_once_or_info!(
        "Upstream Content-Type `{upstream_ct}` differs from the expected `{expected}` for {debname} from {mirror}; caching and serving the file anyway"
    );
}

/// Derive the Content-Type for a cached file based on its filename extension.
#[must_use]
pub(crate) fn content_type_for_cached_file(filename: &str) -> &'static str {
    if deb_mirror::is_deb_package(filename) {
        return "application/vnd.debian.binary-package";
    }

    // Match on the basename so both flat (`Packages`) and structured
    // (`sid_main_binary-amd64_Packages`) debnames classify correctly.
    let basename = filename.rsplit_once('_').map_or(filename, |(_, b)| b);
    if matches!(basename, "InRelease" | "Release" | "Packages" | "Sources") {
        return "text/plain";
    }

    let extension = filename.rsplit_once('.').map(|(_, ext)| ext);

    match extension {
        Some("gz") => "application/gzip",
        Some("xz") => "application/x-xz",
        Some("bz2") => "application/x-bzip2",
        Some("lz4") => "application/x-lz4",
        Some("zst") => "application/zstd",
        Some("gpg") => "application/pgp-signature",
        _ => "application/octet-stream",
    }
}

#[cfg(test)]
mod tests {
    use super::content_type_for_cached_file;

    #[test]
    fn content_type_for_text_manifests() {
        // Flat-repo debnames (no distribution prefix).
        assert_eq!(content_type_for_cached_file("InRelease"), "text/plain");
        assert_eq!(content_type_for_cached_file("Release"), "text/plain");
        assert_eq!(content_type_for_cached_file("Packages"), "text/plain");
        assert_eq!(content_type_for_cached_file("Sources"), "text/plain");

        // Structured-layout debnames (distribution / component / arch prefixes).
        assert_eq!(content_type_for_cached_file("sid_InRelease"), "text/plain");
        assert_eq!(content_type_for_cached_file("sid_Release"), "text/plain");
        assert_eq!(
            content_type_for_cached_file("sid_main_binary-amd64_Release"),
            "text/plain"
        );
        assert_eq!(
            content_type_for_cached_file("sid_main_binary-amd64_Packages"),
            "text/plain"
        );
        assert_eq!(
            content_type_for_cached_file("sid_main_Sources"),
            "text/plain"
        );
    }

    #[test]
    fn content_type_for_release_gpg() {
        assert_eq!(
            content_type_for_cached_file("Release.gpg"),
            "application/pgp-signature"
        );
        assert_eq!(
            content_type_for_cached_file("sid_Release.gpg"),
            "application/pgp-signature"
        );
    }

    #[test]
    fn compressed_manifest_keeps_compression_content_type() {
        // Compressed manifests must keep their compression Content-Type —
        // the `_Packages` suffix on `Packages.gz` must not coerce it to text.
        assert_eq!(
            content_type_for_cached_file("sid_main_binary-amd64_Packages.gz"),
            "application/gzip"
        );
        assert_eq!(
            content_type_for_cached_file("sid_main_Sources.xz"),
            "application/x-xz"
        );
        assert_eq!(
            content_type_for_cached_file("firefox-esr_115.9.1esr-1_amd64.deb"),
            "application/vnd.debian.binary-package"
        );
        assert_eq!(
            content_type_for_cached_file("unknown_no_extension"),
            "application/octet-stream"
        );
    }
}
