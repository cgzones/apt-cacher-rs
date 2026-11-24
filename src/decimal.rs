//! Strict decimal parsing for wire and index fields.

use std::str::FromStr;

/// Parse a `1*DIGIT` field: a `Content-Length`, a byte position, a URI
/// port, a `Release` size. The integers' own `FromStr` also takes a sign
/// (a leading `+` even when unsigned), which none of those grammars allows.
pub(crate) fn parse_digits<T: FromStr>(field: &str) -> Option<T> {
    if field.is_empty() || !field.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    field.parse().ok()
}

#[cfg(test)]
mod tests {
    use std::num::NonZero;

    use super::parse_digits;

    #[test]
    fn only_digits_parse() {
        assert_eq!(parse_digits::<u64>("0"), Some(0));
        assert_eq!(parse_digits::<u64>("007"), Some(7));
        assert_eq!(parse_digits::<u64>("18446744073709551615"), Some(u64::MAX));
        for bad in [
            "",
            "+1",
            "-1",
            " 1",
            "1 ",
            "1_0",
            "0x1",
            "18446744073709551616",
        ] {
            assert_eq!(parse_digits::<u64>(bad), None, "{bad:?}");
        }
        assert_eq!(parse_digits::<i64>("-1"), None);
        // Nor does the "one digit at least" hang on the target refusing "".
        assert_eq!(parse_digits::<String>(""), None);
        // The target type's own range still applies.
        assert_eq!(parse_digits("65535"), NonZero::new(u16::MAX));
        for bad in ["0", "65536"] {
            assert_eq!(parse_digits::<NonZero<u16>>(bad), None, "{bad:?}");
        }
    }
}
