use std::{borrow::Cow, sync::atomic::AtomicBool};

use crate::xattr_helpers::XattrValue;

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
    let Some(etagc) = opaque
        .strip_prefix(b"\"")
        .and_then(|rest| rest.strip_suffix(b"\""))
    else {
        return false;
    };
    etagc
        .iter()
        .all(|&c| c == 0x21 || (0x23..=0x7E).contains(&c) || c >= 0x80)
}

/// A validated `ETag`, persisted on a cached file as
/// `user.apt_cacher_rs.etag` and served back as the response validator.
/// Constructed only by [`XattrValue::parse`], so a stored or written value is
/// always well-formed per RFC 9110 §8.8.3.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ETag(String);

impl ETag {
    pub(crate) fn into_string(self) -> String {
        let Self(etag) = self;
        etag
    }
}

impl XattrValue for ETag {
    const KEY: &'static str = "user.apt_cacher_rs.etag";
    const LABEL: &'static str = "ETag";
    const WRITE_FAILURE_CONSEQUENCE: &'static str =
        "the value will not survive a restart and this file cannot be resumed or revalidated";

    fn discard_gate() -> &'static AtomicBool {
        static GATE: AtomicBool = AtomicBool::new(false);
        &GATE
    }

    fn parse(raw: &str) -> Option<Self> {
        is_valid_etag(raw).then(|| Self(raw.to_owned()))
    }

    fn render(&self) -> Cow<'_, str> {
        let Self(etag) = self;
        Cow::Borrowed(etag)
    }
}

/// Strong `ETag` comparison per RFC 9110 §8.8.3.2: both tags must be strong
/// (i.e. not prefixed with `W/`, so they start with `"`) and identical.
#[must_use]
pub(crate) fn etag_strong_match(a: &str, b: &str) -> bool {
    a.starts_with('"') && b.starts_with('"') && a == b
}

/// Split an `If-None-Match` header value into entity-tag candidates.
///
/// Commas are only treated as list separators when outside a quoted
/// opaque-tag, because RFC 9110 §8.8.3 permits `,` (0x2C) inside the
/// opaque-tag. Each yielded token is trimmed of surrounding OWS.
fn split_if_none_match(header: &str) -> IfNoneMatchSplit<'_> {
    IfNoneMatchSplit {
        header,
        pos: 0,
        done: false,
    }
}

struct IfNoneMatchSplit<'a> {
    header: &'a str,
    pos: usize,
    done: bool,
}

impl<'a> Iterator for IfNoneMatchSplit<'a> {
    type Item = &'a str;

    #[expect(
        clippy::string_slice,
        reason = "splits land on `,` (ASCII) or end-of-string, which are always UTF-8 boundaries"
    )]
    fn next(&mut self) -> Option<&'a str> {
        if self.done {
            return None;
        }
        let bytes = self.header.as_bytes();
        let start = self.pos;
        let mut in_quotes = false;
        let mut i = self.pos;
        while i < bytes.len() {
            match bytes[i] {
                b'"' => in_quotes = !in_quotes,
                b',' if !in_quotes => {
                    let part = &self.header[start..i];
                    self.pos = i + 1;
                    return Some(part.trim());
                }
                _ => {}
            }
            i += 1;
        }
        self.done = true;
        Some(self.header[start..].trim())
    }
}

/// Check if a stored `ETag` matches an `If-None-Match` header value.
///
/// Parses comma-separated values and the `*` wildcard. Uses weak comparison
/// per RFC 9110 §8.8.3.2: the `W/` prefix is stripped before comparing opaque-tags.
#[must_use]
pub(crate) fn if_none_match(header: &str, etag: &str) -> bool {
    /// RFC 9110 allows long If-None-Match lists, but a sane client sends a
    /// handful. Refuse to scan absurdly long lists - returning `false`
    /// means the client gets a normal `200`, never a stale `304`.
    const MAX_IF_NONE_MATCH_ENTRIES: usize = 64;

    let stored = etag_opaque_tag(etag);
    // A stored value that is not a quoted opaque-tag can never be equivalent
    // to a well-formed candidate; only the `*` wildcard still matches.
    let stored_is_tag = stored.starts_with('"');
    split_if_none_match(header)
        .take(MAX_IF_NONE_MATCH_ENTRIES)
        .any(|part| part == "*" || (stored_is_tag && etag_opaque_tag(part) == stored))
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
        // Only a leading `W/` is the weak indicator; inside the opaque-tag it
        // is ordinary etagc.
        assert!(is_valid_etag("\"W/\""));
        assert!(!is_valid_etag("W/W/\"abc\""));
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
        // Weak comparison: W/"abc" matches "abc" (RFC 9110 §8.8.3.2)
        assert!(if_none_match("W/\"abc\"", "\"abc\""));
        assert!(if_none_match("\"abc\"", "W/\"abc\""));
        assert!(if_none_match("W/\"abc\"", "W/\"abc\""));
        assert!(!if_none_match("W/\"abc\"", "\"def\""));
    }

    #[test]
    fn if_none_match_wildcard_and_degenerate_headers() {
        // `*` matches wherever it appears in the list, and regardless of what
        // is stored -- RFC 9110 section 13.1.2 makes it "any current
        // representation".
        assert!(if_none_match("\"x\", *", "\"abc\""));
        assert!(if_none_match("*, \"x\"", "\"abc\""));
        assert!(if_none_match("*", "not-a-tag"));

        // A stored value that is not a quoted opaque-tag never matches a
        // candidate; only `*` above can.
        assert!(!if_none_match("\"abc\"", "abc"));
        assert!(!if_none_match("abc", "abc"));

        // Degenerate headers must be false, not a panic: the split still
        // yields one (empty) token.
        assert!(!if_none_match("", "\"abc\""));
        assert!(!if_none_match("   ", "\"abc\""));
        assert!(!if_none_match(",", "\"abc\""));
    }

    #[test]
    fn if_none_match_caps_at_max_entries() {
        // Build a header where "target" only appears at index 64 (past the cap of 64).
        // The first 64 entries are all "x" (indices 0..63), then "target" at index 64.
        // The cap stops scanning at index 64, so "target" is never reached.
        let mut parts = vec!["\"x\""; 64];
        parts.push("\"target\"");
        let header = parts.join(",");
        assert!(!if_none_match(&header, "\"target\""));
    }

    #[test]
    fn if_none_match_finds_within_cap() {
        // The matching value is at position 0; well within MAX_IF_NONE_MATCH_ENTRIES.
        let header = "\"abc\", \"x\", \"y\"";
        assert!(if_none_match(header, "\"abc\""));
    }

    #[test]
    fn if_none_match_handles_comma_inside_opaque_tag() {
        // RFC 9110 §8.8.3 etagc includes 0x2C (','), so `"a,b"` is a valid ETag.
        // The split must not treat that comma as a list separator.
        assert!(is_valid_etag("\"a,b\""));
        // Single-entry list whose only ETag contains a comma.
        assert!(if_none_match("\"a,b\"", "\"a,b\""));
        // Same ETag embedded in the middle of a list, with OWS.
        assert!(if_none_match("\"x\", \"a,b\", \"y\"", "\"a,b\""));
        // First and last positions of the list.
        assert!(if_none_match("\"a,b\", \"x\"", "\"a,b\""));
        assert!(if_none_match("\"x\", \"a,b\"", "\"a,b\""));
        // Multiple commas inside one opaque-tag, plus a peer entry.
        assert!(if_none_match("\"a,b,c\", \"d\"", "\"a,b,c\""));
        // Weak form on either side: weak comparison still strips W/.
        assert!(if_none_match("W/\"a,b\"", "\"a,b\""));
        assert!(if_none_match("\"a,b\"", "W/\"a,b\""));
        assert!(if_none_match("W/\"a,b\", \"x\"", "\"a,b\""));
    }

    #[test]
    fn if_none_match_rejects_substrings_of_comma_etag() {
        // Stored `"a"` must NOT match a header that only contains `"a,b"`:
        // the comma is inside the opaque-tag, not a separator.
        assert!(!if_none_match("\"a,b\"", "\"a\""));
        assert!(!if_none_match("\"a,b\"", "\"b\""));
        // And the inverse: stored `"a,b"` is not present in a list of `"a"`, `"b"`.
        assert!(!if_none_match("\"a\", \"b\"", "\"a,b\""));
    }

    #[test]
    fn if_none_match_malformed_unterminated_quote_does_not_match() {
        // An unterminated quoted token can't be parsed as a valid entity-tag, so
        // it must not match a well-formed stored ETag. Importantly, it also must
        // not panic or read past the end.
        assert!(!if_none_match("\"abc", "\"abc\""));
        assert!(!if_none_match("\"abc, \"def\"", "\"def\""));
    }

    #[test]
    fn etag_parse_and_render() {
        let strong = ETag::parse("\"abc\"").expect("strong ETag");
        assert_eq!(strong.render(), "\"abc\"");
        assert_eq!(strong.into_string(), "\"abc\"");
        let weak = ETag::parse("W/\"abc\"").expect("weak ETag");
        assert_eq!(weak.render(), "W/\"abc\"");
        assert!(ETag::parse("abc").is_none());
        assert!(ETag::parse("").is_none());
        assert!(ETag::parse("\"a b\"").is_none());
    }

    #[test]
    fn etag_scrubs_malformed_and_round_trips() {
        use crate::xattr_helpers::tests::assert_scrubs_malformed_and_round_trips;

        let valid = ETag::parse("\"306ed-61a5ca11810f3\"").expect("valid ETag");
        assert_scrubs_malformed_and_round_trips(b"unquoted", &valid);
        assert_scrubs_malformed_and_round_trips(b"\"\xff\"", &ETag::parse("W/\"w\"").unwrap());
    }
}
