use std::path::Path;

use log::{info, warn};

use crate::xattr_helpers;

/// The extended attribute name used to store `ETag` values.
const XATTR_ETAG: &str = "user.apt_cacher_rs.etag";

/// Return the opaque-tag portion of an `ETag`, stripping the `W/` prefix if present.
///
/// Used for weak comparison per RFC 9110 §8.8.3.2: two `ETag`s are weakly equivalent
/// if their opaque-tags match, regardless of the weak indicator.
#[must_use]
fn etag_opaque_tag(s: &str) -> &str {
    s.strip_prefix("W/").unwrap_or(s)
}

/// Validate that a string is a well-formed `ETag` per RFC 9110 §8.8.3.
///
/// Accepts both strong (`"<etagc>"`) and weak (`W/"<etagc>"`) forms, where etagc consists
/// of `0x21` or `0x23..=0x7E` or bytes `>= 0x80` (obs-text).
/// For now only valid UTF-8 sequences are accepted.
/// Note that an empty `ETag` (`""`) is valid.
#[must_use]
pub(crate) fn is_valid_etag(s: &str) -> bool {
    let opaque = etag_opaque_tag(s).as_bytes();
    opaque.len() >= 2
        && opaque[0] == b'"'
        && opaque[opaque.len() - 1] == b'"'
        && opaque[1..opaque.len() - 1]
            .iter()
            .all(|&c| c == 0x21 || (0x23..=0x7E).contains(&c) || c >= 0x80)
}

/// Read an `ETag` from the file's extended attributes.
///
/// Returns `None` on any error (graceful degradation).
#[must_use]
pub(crate) fn read_etag(file: &tokio::fs::File, display_path: &Path) -> Option<String> {
    let data = xattr_helpers::read_helper(file, display_path, XATTR_ETAG)?;

    if !is_valid_etag(&data) {
        warn!(
            "Discarding malformed ETag from `{}`: {}",
            display_path.display(),
            data.escape_debug()
        );

        xattr_helpers::remove_helper(file, display_path, XATTR_ETAG);

        return None;
    }

    Some(data)
}

/// Write an `ETag` to the file's extended attributes.
///
/// Malformed values are skipped. Logs warnings on failure but never propagates errors.
pub(crate) fn write_etag(file: &tokio::fs::File, display_path: &Path, etag: &str) {
    if !is_valid_etag(etag) {
        info!(
            "Skipping write of malformed ETag to `{}`: {}",
            display_path.display(),
            etag.escape_debug()
        );
        return;
    }

    xattr_helpers::write_helper(file, display_path, XATTR_ETAG, etag.as_bytes());
}

/// Strong `ETag` comparison per RFC 9110 §8.8.3.2: both tags must be strong
/// (i.e. not prefixed with `W/`, so they start with `"`) and identical.
#[must_use]
pub(crate) fn etag_strong_match(a: &str, b: &str) -> bool {
    a.starts_with('"') && b.starts_with('"') && a == b
}

/// Check if a stored `ETag` matches an `If-None-Match` header value.
///
/// Parses comma-separated values and the `*` wildcard. Uses weak comparison
/// per RFC 9110 §13.1.2: the `W/` prefix is stripped before comparing opaque-tags.
#[must_use]
pub(crate) fn if_none_match(header: &str, etag: &str) -> bool {
    let stored = etag_opaque_tag(etag);
    for part in header.split(',') {
        let part = part.trim();
        if part == "*" {
            return true;
        }
        if etag_opaque_tag(part) == stored && stored.starts_with('"') {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_valid_etag_test() {
        // Valid strong ETags
        assert!(is_valid_etag("\"abc\""));
        assert!(is_valid_etag("\"\""));
        assert!(is_valid_etag("\"306ed-61a5ca11810f3\""));
        // space (0x20) is not in etagc
        assert!(!is_valid_etag("\"a b c\""));
        // 0x21 is '!'
        assert!(is_valid_etag("\"!\""));
        // 0x23..=0x7E
        assert!(is_valid_etag("\"#~\""));
        // obs-text (>= 0x80)
        assert!(is_valid_etag("\"caffe\u{e9}\""));

        // Valid weak ETags
        assert!(is_valid_etag("W/\"abc\""));
        assert!(is_valid_etag("W/\"\""));
        assert!(is_valid_etag("W/\"306ed-61a5ca11810f3\""));

        // Invalid: not quoted
        assert!(!is_valid_etag("abc"));
        assert!(!is_valid_etag(""));
        // Invalid: malformed weak prefix
        assert!(!is_valid_etag("W/abc"));
        // Invalid: contains forbidden 0x22 (double-quote) inside
        assert!(!is_valid_etag("\"a\"b\""));
        // Invalid: contains DEL (0x7F)
        assert!(!is_valid_etag("\"a\x7Fb\""));
        // Invalid: contains control chars
        assert!(!is_valid_etag("\"a\x00b\""));
        assert!(!is_valid_etag("\"a\nb\""));
        assert!(!is_valid_etag("\"a\rb\""));
        // Invalid: single quote only
        assert!(!is_valid_etag("\""));
    }

    #[test]
    fn etag_matches_test() {
        assert!(etag_strong_match("\"abc\"", "\"abc\""));
        assert!(!etag_strong_match("\"abc\"", "\"def\""));
        assert!(!etag_strong_match("W/\"abc\"", "\"abc\""));
        assert!(!etag_strong_match("\"abc\"", "W/\"abc\""));
        assert!(!etag_strong_match("abc", "abc"));
        assert!(!etag_strong_match("", ""));
    }

    #[test]
    fn if_none_match_test() {
        assert!(if_none_match("\"abc\"", "\"abc\""));
        assert!(!if_none_match("\"abc\"", "\"def\""));
        assert!(if_none_match("*", "\"abc\""));
        assert!(if_none_match("\"x\", \"abc\", \"y\"", "\"abc\""));
        assert!(!if_none_match("\"x\", \"y\"", "\"abc\""));
        assert!(if_none_match("\"x\" , \"abc\"", "\"abc\""));
        // Weak comparison: W/"abc" matches "abc" (RFC 9110 §13.1.2)
        assert!(if_none_match("W/\"abc\"", "\"abc\""));
        assert!(if_none_match("\"abc\"", "W/\"abc\""));
        assert!(if_none_match("W/\"abc\"", "W/\"abc\""));
        assert!(!if_none_match("W/\"abc\"", "\"def\""));
    }
}
