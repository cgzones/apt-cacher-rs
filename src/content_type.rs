//! `Content-Type` for a cached file, derived from its debname, and the
//! once-per-value warning when upstream announces a different type.

use crate::{deb_mirror, warn_once_or_info};

/// Whether an upstream `Content-Type` is acceptable for a file whose name
/// implies `expected` (as [`content_type_for_cached_file`] derives it).
///
/// Comparison is case-insensitive, and three historical spellings Debian
/// mirrors still emit count as equal rather than as a mismatch worth
/// logging:
///
/// - `binary/octet-stream`, a non-standard spelling advertised for
///   everything by many mirrors;
/// - `application/x-deb`, the unregistered alias for the IANA-registered
///   `application/vnd.debian.binary-package`;
/// - `application/x-gzip`, the non-standard alias for the IANA-registered
///   `application/gzip` (RFC 6713).
#[must_use]
fn content_type_matches(upstream: &str, expected: &str) -> bool {
    if upstream.eq_ignore_ascii_case(expected)
        || upstream.eq_ignore_ascii_case("binary/octet-stream")
    {
        return true;
    }
    let legacy_alias = match expected {
        "application/vnd.debian.binary-package" => "application/x-deb",
        "application/gzip" => "application/x-gzip",
        _ => return false,
    };
    upstream.eq_ignore_ascii_case(legacy_alias)
}

/// Warn (once) if the upstream `Content-Type` is not one
/// [`content_type_matches`] accepts for the cached file's name.
pub(crate) fn warn_on_content_type_mismatch(
    upstream: Option<&str>,
    mirror: &deb_mirror::Mirror,
    debname: &str,
) {
    let Some(upstream_ct) = upstream else {
        return;
    };
    let expected = content_type_for_cached_file(debname);
    if content_type_matches(upstream_ct, expected) {
        return;
    }
    warn_once_or_info!(
        "Upstream Content-Type `{upstream_ct}` differs from the expected `{expected}` for {debname} from {mirror}; caching and serving the file anyway"
    );
}

/// Derive the `Content-Type` for a cached file from its debname: the deb
/// predicate first, then the manifest basenames, then the extension.
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
    use super::{content_type_for_cached_file, content_type_matches};

    #[test]
    fn content_type_matches_accepts_case_and_legacy_aliases() {
        // Exact, and case-insensitively so (RFC 9110 section 8.3).
        assert!(content_type_matches("text/plain", "text/plain"));
        assert!(content_type_matches("TEXT/PLAIN", "text/plain"));

        // The non-standard catch-all every Debian mirror emits.
        assert!(content_type_matches("binary/octet-stream", "text/plain"));
        assert!(content_type_matches(
            "Binary/Octet-Stream",
            "application/gzip"
        ));

        // Legacy aliases, each only for the type it aliases.
        assert!(content_type_matches(
            "application/x-deb",
            "application/vnd.debian.binary-package"
        ));
        assert!(content_type_matches(
            "application/x-gzip",
            "application/gzip"
        ));
        assert!(!content_type_matches("application/x-gzip", "text/plain"));
        assert!(!content_type_matches(
            "application/x-deb",
            "application/gzip"
        ));

        // Anything else is a mismatch worth the once-per-process warning.
        assert!(!content_type_matches("text/html", "text/plain"));
        assert!(!content_type_matches("", "text/plain"));
        assert!(!content_type_matches(
            "application/octet-stream",
            "application/gzip"
        ));
    }

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
