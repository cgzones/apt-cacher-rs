use std::{borrow::Cow, sync::atomic::AtomicBool};

use crate::{http_range::HttpDate, xattr_helpers::XattrValue};

/// Validate that a string is a parseable HTTP-date per RFC 9110 §5.6.7,
/// IMF-fixdate form only - legacy RFC 850 and asctime are rejected as
/// malformed.  The underlying `HttpDate::parse` only accepts IMF-fixdate
/// (and the RFC 2822 superset); broadening that parser is a behaviour
/// change, out of scope here.
#[must_use]
pub(crate) fn is_valid_http_date(s: &str) -> bool {
    HttpDate::parse(s).is_some()
}

/// A validated upstream `Last-Modified` value, persisted on a cached file as
/// `user.apt_cacher_rs.last_modified` (RFC 9110 §10.2.2: forward the
/// origin's value). Carries both the raw header string (for the
/// `Last-Modified` response header) and its parsed [`HttpDate`] (for
/// `If-Modified-Since` comparison), so consumers never re-parse.
/// Constructed only by [`XattrValue::parse`], so it is always an IMF-fixdate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct LastModified {
    raw: String,
    time: HttpDate,
}

impl LastModified {
    pub(crate) fn into_parts(self) -> (String, HttpDate) {
        let Self { raw, time } = self;
        (raw, time)
    }
}

impl XattrValue for LastModified {
    const KEY: &'static str = "user.apt_cacher_rs.last_modified";
    const LABEL: &'static str = "Last-Modified";
    const WRITE_FAILURE_CONSEQUENCE: &'static str =
        "the value will not survive a restart and this file cannot be revalidated by date";

    fn discard_gate() -> &'static AtomicBool {
        static GATE: AtomicBool = AtomicBool::new(false);
        &GATE
    }

    fn parse(raw: &str) -> Option<Self> {
        HttpDate::parse(raw).map(|time| Self {
            raw: raw.to_owned(),
            time,
        })
    }

    fn render(&self) -> Cow<'_, str> {
        let Self { raw, time: _ } = self;
        Cow::Borrowed(raw)
    }
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

    #[test]
    fn last_modified_parse_and_render() {
        let value = "Tue, 21 Mar 2361 19:15:09 GMT";
        let parsed = LastModified::parse(value).expect("IMF-fixdate");
        assert_eq!(parsed.render(), value);
        let (raw, time) = parsed.into_parts();
        assert_eq!(raw, value);
        assert_eq!(time, HttpDate::from_secs(12_345_678_909));
        assert!(LastModified::parse("garbage").is_none());
        assert!(LastModified::parse("").is_none());
    }

    #[test]
    fn last_modified_scrubs_malformed_and_round_trips() {
        use crate::xattr_helpers::tests::assert_scrubs_malformed_and_round_trips;

        let valid = LastModified::parse("Thu, 01 Jan 1970 00:00:00 GMT").expect("valid date");
        assert_scrubs_malformed_and_round_trips(b"garbage", &valid);
        assert_scrubs_malformed_and_round_trips(b"Thu, 32 Jan 1970 00:00:00 GMT", &valid);
    }
}
