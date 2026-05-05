use std::cmp::min;
use std::fmt::Write as _;
use std::time::{SystemTime, SystemTimeError};

use time::format_description::FormatItem;
use time::format_description::well_known::Rfc2822;
use time::macros::format_description;
use time::{OffsetDateTime, macros::offset};

use crate::http_etag::etag_strong_match;
use crate::warn_once_or_info;

const HTTP_DATE_FORMAT: &[FormatItem<'_>] = format_description!(
    "[weekday repr:short], [day] [month repr:short] [year] [hour]:[minute]:[second] GMT"
);

/// A wall-clock point in time at HTTP-date (1-second) granularity.
///
/// HTTP date headers (RFC 9110 §5.6.7, IMF-fixdate) encode whole seconds since the
/// Unix epoch, so this is the natural precision for `Last-Modified`, `If-Range`,
/// `If-Modified-Since`, and the `Date` header.
///
/// All constructors clamp the stored value to [`Self::MAX_SECS`] (i.e. `i64::MAX`),
/// so conversion to `i64` — required by `OffsetDateTime::from_unix_timestamp` — is
/// guaranteed to be lossless. `i64::MAX` seconds is ~292 billion years, so this cap
/// is not a practical limitation.
///
/// The current value is read via [`HttpDate::now`], which uses
/// `coarsetime::Clock::now_since_epoch()` (`CLOCK_REALTIME_COARSE` on Linux — a
/// jiffy-updated read, much cheaper than `SystemTime::now()`).
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct HttpDate(u64);

impl HttpDate {
    pub(crate) const UNIX_EPOCH: Self = Self(0);

    /// Inclusive upper bound on the stored seconds value.
    ///
    /// Equals `i64::MAX`. Written as `u64::MAX >> 1` (rather than `i64::MAX as u64`)
    /// to avoid triggering `clippy::cast_sign_loss`.
    const MAX_SECS: u64 = u64::MAX >> 1;

    /// Construct a value, clamping at [`Self::MAX_SECS`].
    #[must_use]
    fn clamped(secs: u64) -> Self {
        Self(secs.min(Self::MAX_SECS))
    }

    /// Current wall-clock time truncated to whole seconds.
    #[must_use]
    pub(crate) fn now() -> Self {
        Self::clamped(coarsetime::Clock::now_since_epoch().as_secs())
    }

    /// Whole seconds elapsed from `self` to now, None for future dates.
    #[must_use]
    pub(crate) fn elapsed_secs(self) -> Option<u64> {
        Self::now().0.checked_sub(self.0)
    }

    /// Format as an IMF-fixdate string (e.g. `Sun, 06 Nov 1994 08:49:37 GMT`).
    #[must_use]
    pub(crate) fn format(self) -> String {
        let secs_i64 =
            i64::try_from(self.0).expect("HttpDate is clamped to i64::MAX by construction");
        let odt = OffsetDateTime::from_unix_timestamp(secs_i64)
            .expect("HttpDate should be representable as OffsetDateTime");
        debug_assert_eq!(odt.offset(), offset!(UTC), "offset should be UTC");
        odt.format(HTTP_DATE_FORMAT).expect("date should be valid")
    }

    /// Parse an RFC 2822 / IMF-fixdate string. Returns `None` for malformed input
    /// or dates before the Unix epoch.
    #[must_use]
    pub(crate) fn parse(s: &str) -> Option<Self> {
        let odt = OffsetDateTime::parse(s, &Rfc2822).ok()?;
        // `unix_timestamp()` returns i64; non-negative values are therefore
        // always `<= i64::MAX == Self::MAX_SECS`, so no further clamping is
        // needed after the unsigned conversion.
        u64::try_from(odt.unix_timestamp()).ok().map(Self)
    }
}

#[cfg(test)]
impl HttpDate {
    pub(crate) fn from_secs(secs: u64) -> Self {
        Self::clamped(secs)
    }
}

impl From<SystemTime> for HttpDate {
    /// Converts a `SystemTime` to `HttpDate`, rounding up any sub-second component
    /// and clamping to [`HttpDate::MAX_SECS`].
    ///
    /// Rounding up matches HTTP semantics: if a file changed at T+0.5s, reporting
    /// `Last-Modified: T+1` is safe — an `If-Modified-Since: T` request correctly
    /// reports "modified" rather than serving a stale 304.
    fn from(t: SystemTime) -> Self {
        match t.duration_since(SystemTime::UNIX_EPOCH) {
            Ok(d) => {
                let secs = d.as_secs();
                let rounded = if d.subsec_nanos() == 0 {
                    secs
                } else {
                    secs.saturating_add(1)
                };
                Self::clamped(rounded)
            }
            Err(_e @ SystemTimeError { .. }) => {
                // If the system time is before the Unix epoch, return the Unix epoch
                Self::UNIX_EPOCH
            }
        }
    }
}

/// Format the current date and time as an HTTP date string.
///
/// Cached at 1-second granularity.
#[must_use]
pub(crate) fn format_http_date() -> String {
    static CACHE: std::sync::LazyLock<parking_lot::Mutex<(HttpDate, String)>> =
        std::sync::LazyLock::new(|| parking_lot::Mutex::new((HttpDate(u64::MAX), String::new())));

    let now = HttpDate::now();

    {
        let cached = CACHE.lock();
        if cached.0 == now {
            return cached.1.clone();
        }
    }

    let formatted = now.format();

    {
        let mut cached = CACHE.lock();
        if cached.0 != now {
            cached.0 = now;
            cached.1.clone_from(&formatted);
        }
    }

    formatted
}

/// Maximum value for the HTTP `Age` header, per RFC 9111 §5.1.
///
/// "If a cache receives a value larger than the largest positive integer it can represent,
/// or if any of its age calculations overflows, it MUST transmit an Age field value of
/// 2147483648 (2^31)."
pub(crate) const AGE_OVERFLOW_VALUE: u64 = 1u64 << 31;

/// Return the timestamp considered representative of when a cached file was last replaced.
///
/// Permanent cache entries are replaced atomically (rename-over), so the file's creation
/// timestamp is the best proxy for "when did this content first appear in the cache" and is
/// used when the filesystem reports it.
///
/// On filesystems without birth-time support the function falls back to the modification
/// timestamp. This has a subtle consequence for *volatile* files: revalidation touches the
/// mtime (see `touch_volatile_mtime`) to record the last upstream check, so on non-btime
/// filesystems the returned timestamp tracks that instead of the original creation time.
/// Permanent entries are unaffected since they are never mtime-touched after rename.
#[must_use]
pub(crate) fn cache_file_http_date(metadata: &std::fs::Metadata) -> HttpDate {
    let st = metadata.created().unwrap_or_else(|_err| {
        metadata
            .modified()
            .expect("Platform should support modification timestamps via setup check")
    });
    HttpDate::from(st)
}

/// Compute the HTTP `Age` header value (in seconds) for a cached file.
///
/// Uses the file's creation timestamp (or modification timestamp as fallback). Saturates to
/// `AGE_OVERFLOW_VALUE` per RFC 9111 §5.1, and returns 0 if the timestamp is somehow in the
/// future (e.g. clock skew).
#[must_use]
pub(crate) fn compute_age(metadata: &std::fs::Metadata) -> u32 {
    let age = cache_file_http_date(metadata).elapsed_secs().unwrap_or(0);
    age.min(AGE_OVERFLOW_VALUE) as u32
}

/// Result of parsing an HTTP Range request header.
pub(crate) enum ParsedRange {
    /// Valid, satisfiable range: Content-Range header value, start byte, content length.
    Satisfiable(String, u64, u64),
    /// The Range header is syntactically malformed. Per RFC 7233 §4.4, the recipient
    /// should ignore the header and serve the full entity (200).
    Invalid,
    /// The Range is syntactically valid but unsatisfiable for this file size (416).
    NotSatisfiable,
    /// The range is valid but the `If-Range` precondition failed; serve the full entity (200).
    IfRangeFailed,
}

/// Computes the requested bytes range.
#[must_use]
pub(crate) fn http_parse_range(
    range: &str,
    if_range: Option<&str>,
    file_size: u64,
    cache_time: HttpDate,
    file_etag: Option<&str>,
) -> ParsedRange {
    /* See RFC 7233 Section 2.1: https://www.rfc-editor.org/rfc/rfc7233.html#section-2.1 */

    // TODO: support multiple ranges: bytes=500-600,601-999  --  bytes=500-700,601-999

    let Some(byte_range) = range.strip_prefix("bytes=") else {
        return ParsedRange::Invalid;
    };
    if byte_range.contains(',') {
        warn_once_or_info!(
            "HTTP Range Request with multiple ranges are not supported (`{byte_range}`)"
        );
        return ParsedRange::Invalid;
    }
    let Some((start, end)) = byte_range.split_once('-') else {
        return ParsedRange::Invalid;
    };

    let start = if start.is_empty() {
        None
    } else {
        let Ok(s) = start.parse::<u64>() else {
            return ParsedRange::Invalid;
        };
        Some(s)
    };
    let end = if end.is_empty() {
        None
    } else {
        let Ok(e) = end.parse::<u64>() else {
            return ParsedRange::Invalid;
        };
        Some(e)
    };

    if file_size == 0 {
        // A zero-length entity admits no satisfiable byte range. Per RFC 7233 §2.1,
        // a server that supports Range MAY ignore the header for zero-length content.
        return ParsedRange::NotSatisfiable;
    }

    let (start, end) = match (start, end) {
        // "bytes=-" is malformed: neither a first-byte-pos nor a suffix-length
        (None, None) => return ParsedRange::Invalid,
        (Some(s), Some(e)) => {
            if s > e {
                // first-byte-pos > last-byte-pos is syntactically invalid
                return ParsedRange::Invalid;
            }
            if s >= file_size {
                return ParsedRange::NotSatisfiable;
            }
            (s, min(e, file_size - 1))
        }
        (Some(s), None) => {
            if s >= file_size {
                return ParsedRange::NotSatisfiable;
            }
            (s, file_size - 1)
        }
        (None, Some(e)) => {
            if e == 0 {
                return ParsedRange::NotSatisfiable;
            }
            (file_size.saturating_sub(e), file_size - 1)
        }
    };

    if let Some(if_range) = if_range {
        let matched = if if_range.starts_with('"') {
            // Strong ETag comparison
            matches!(file_etag, Some(etag) if etag_strong_match(if_range, etag))
        } else if if_range.starts_with("W/") {
            // Weak ETags are not allowed in If-Range (RFC 7233 §3.2)
            false
        } else {
            match HttpDate::parse(if_range) {
                Some(if_time) => if_time >= cache_time,
                // Unparsable If-Range date: treat as failed precondition
                None => false,
            }
        };
        if !matched {
            return ParsedRange::IfRangeFailed;
        }
    }

    debug_assert!(start <= end, "start {start} must not exceed end {end}");
    debug_assert!(
        end < file_size,
        "end {end} must be less than file_size {file_size}"
    );

    let content_length = end - start + 1;
    debug_assert!(
        start + content_length <= file_size,
        "range {start}+{content_length} must not exceed file_size {file_size}"
    );

    let mut content_range = String::with_capacity(32);
    write!(content_range, "bytes {start}-{end}/{file_size}")
        .expect("writing to a String never fails");
    ParsedRange::Satisfiable(content_range, start, content_length)
}

/// Parse an HTTP `Content-Range` response header value.
///
/// Expects the format `bytes {start}-{end}/{total}` and returns `(start, end, total)`.
#[must_use]
pub(crate) fn parse_content_range(value: &str) -> Option<(u64, u64, u64)> {
    let rest = value.strip_prefix("bytes ")?;
    let (range_part, total_str) = rest.split_once('/')?;
    let (start_str, end_str) = range_part.split_once('-')?;

    let start = start_str.parse::<u64>().ok()?;
    let end = end_str.parse::<u64>().ok()?;
    let total = total_str.parse::<u64>().ok()?;

    if start > end || end >= total {
        return None;
    }

    Some((start, end, total))
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use crate::http_range::{HttpDate, ParsedRange, http_parse_range, parse_content_range};

    /// Helper to unwrap a `ParsedRange::Satisfiable` for concise test assertions.
    fn satisfiable(r: ParsedRange) -> Option<(String, u64, u64)> {
        match r {
            ParsedRange::Satisfiable(cr, s, l) => Some((cr, s, l)),
            ParsedRange::Invalid | ParsedRange::NotSatisfiable | ParsedRange::IfRangeFailed => None,
        }
    }

    #[test]
    fn format_datetime_test() {
        assert_eq!(
            HttpDate::UNIX_EPOCH.format(),
            "Thu, 01 Jan 1970 00:00:00 GMT"
        );

        assert_eq!(
            HttpDate::from_secs(12_345_678_909).format(),
            "Tue, 21 Mar 2361 19:15:09 GMT"
        );

        // Sub-second SystemTimes round up to the next whole second.
        assert_eq!(
            HttpDate::from(UNIX_EPOCH + Duration::from_nanos(1)).format(),
            "Thu, 01 Jan 1970 00:00:01 GMT"
        );

        assert_eq!(
            HttpDate::from(UNIX_EPOCH + Duration::from_nanos(999_999_999)).format(),
            "Thu, 01 Jan 1970 00:00:01 GMT"
        );
    }

    #[test]
    fn parse_datetime_test() {
        assert_eq!(
            HttpDate::parse("Thu, 01 Jan 1970 00:00:00 GMT"),
            Some(HttpDate::UNIX_EPOCH)
        );

        assert_eq!(
            HttpDate::parse("Tue, 21 Mar 2361 19:15:09 GMT"),
            Some(HttpDate::from_secs(12_345_678_909))
        );
    }

    #[test]
    fn clamps_to_i64_max() {
        // An out-of-range seconds value must clamp so the stored seconds always
        // fit in i64 — that's what makes the cast in `HttpDate::format` lossless.
        assert!(i64::try_from(HttpDate::from_secs(u64::MAX).0).is_ok());
        assert_eq!(
            HttpDate::from_secs(u64::MAX),
            HttpDate::from_secs(u64::MAX - 1),
            "values above i64::MAX must saturate to the same clamped HttpDate"
        );
    }

    #[test]
    fn systemtime_round_trip() {
        // Whole seconds pass through unchanged.
        assert_eq!(
            HttpDate::from(SystemTime::UNIX_EPOCH + Duration::from_secs(42)),
            HttpDate::from_secs(42)
        );
        // Pre-epoch clocks saturate to UNIX_EPOCH.
        assert_eq!(
            HttpDate::from(SystemTime::UNIX_EPOCH - Duration::from_secs(1)),
            HttpDate::UNIX_EPOCH
        );
    }

    #[test]
    fn parse_http_range_test() {
        /*
         * valid
         */

        assert_eq!(
            satisfiable(http_parse_range(
                "bytes=0-1023",
                Some("Tue, 21 Mar 2361 19:15:09 GMT"),
                8192,
                HttpDate::UNIX_EPOCH,
                None,
            )),
            Some(("bytes 0-1023/8192".to_string(), 0, 1024))
        );

        assert_eq!(
            satisfiable(http_parse_range(
                "bytes=0-1023",
                None,
                8192,
                HttpDate::UNIX_EPOCH,
                None
            )),
            Some(("bytes 0-1023/8192".to_string(), 0, 1024))
        );

        assert_eq!(
            satisfiable(http_parse_range(
                "bytes=5000-6999",
                None,
                10000,
                HttpDate::UNIX_EPOCH,
                None
            )),
            Some(("bytes 5000-6999/10000".to_string(), 5000, 2000))
        );

        assert_eq!(
            satisfiable(http_parse_range(
                "bytes=5000-6999",
                None,
                6000,
                HttpDate::UNIX_EPOCH,
                None
            )),
            Some(("bytes 5000-5999/6000".to_string(), 5000, 1000))
        );

        assert_eq!(
            satisfiable(http_parse_range(
                "bytes=0-0",
                None,
                10000,
                HttpDate::UNIX_EPOCH,
                None
            )),
            Some(("bytes 0-0/10000".to_string(), 0, 1))
        );

        assert_eq!(
            satisfiable(http_parse_range(
                "bytes=9999-9999",
                None,
                10000,
                HttpDate::UNIX_EPOCH,
                None
            )),
            Some(("bytes 9999-9999/10000".to_string(), 9999, 1))
        );

        assert_eq!(
            satisfiable(http_parse_range(
                "bytes=-1",
                None,
                10000,
                HttpDate::UNIX_EPOCH,
                None
            )),
            Some(("bytes 9999-9999/10000".to_string(), 9999, 1))
        );

        assert_eq!(
            satisfiable(http_parse_range(
                "bytes=-500",
                None,
                10000,
                HttpDate::UNIX_EPOCH,
                None
            )),
            Some(("bytes 9500-9999/10000".to_string(), 9500, 500))
        );

        assert_eq!(
            satisfiable(http_parse_range(
                "bytes=-1000",
                None,
                400,
                HttpDate::UNIX_EPOCH,
                None
            )),
            Some(("bytes 0-399/400".to_string(), 0, 400))
        );

        assert_eq!(
            satisfiable(http_parse_range(
                "bytes=4096-",
                None,
                10000,
                HttpDate::UNIX_EPOCH,
                None
            )),
            Some(("bytes 4096-9999/10000".to_string(), 4096, 5904))
        );

        /* Sub-second cache time rounds up: If-Range = 1s matches rounded cache = 1s */

        assert_eq!(
            satisfiable(http_parse_range(
                "bytes=0-1023",
                Some("Thu, 01 Jan 1970 00:00:01 GMT"),
                8192,
                HttpDate::from(UNIX_EPOCH + Duration::from_millis(500)),
                None,
            )),
            Some(("bytes 0-1023/8192".to_string(), 0, 1024))
        );

        /* If-Range time older than cache time: IfRangeFailed */
        assert!(matches!(
            http_parse_range(
                "bytes=0-1023",
                Some("Thu, 01 Jan 1970 00:00:00 GMT"),
                8192,
                HttpDate::from(UNIX_EPOCH + Duration::from_millis(500)),
                None,
            ),
            ParsedRange::IfRangeFailed
        ));

        /*
         * not satisfiable
         */

        /* empty file */
        assert!(matches!(
            http_parse_range(
                "bytes=0-1023",
                Some("Tue, 21 Mar 2361 19:15:09 GMT"),
                0,
                HttpDate::UNIX_EPOCH,
                None,
            ),
            ParsedRange::NotSatisfiable
        ));

        /* start out-of-range */
        assert!(matches!(
            http_parse_range(
                "bytes=9999-99999",
                Some("Tue, 21 Mar 2361 19:15:09 GMT"),
                8192,
                HttpDate::UNIX_EPOCH,
                None,
            ),
            ParsedRange::NotSatisfiable
        ));

        /* end less than start: syntactically invalid, ignore per RFC 7233 §4.4 */
        assert!(matches!(
            http_parse_range(
                "bytes=1023-0",
                Some("Tue, 21 Mar 2361 19:15:09 GMT"),
                8192,
                HttpDate::UNIX_EPOCH,
                None,
            ),
            ParsedRange::Invalid
        ));

        /* outdated If-Range */
        assert!(matches!(
            http_parse_range(
                "bytes=0-1023",
                Some("Tue, 21 Mar 2361 19:15:09 GMT"),
                8192,
                HttpDate::from_secs(12_345_678_910),
                None,
            ),
            ParsedRange::IfRangeFailed
        ));

        assert!(matches!(
            http_parse_range("bytes=4000-5999", None, 3000, HttpDate::UNIX_EPOCH, None),
            ParsedRange::NotSatisfiable
        ));

        /* unparsable If-Range date */
        assert!(matches!(
            http_parse_range(
                "bytes=0-1023",
                Some("ABCDEFG"),
                8192,
                HttpDate::UNIX_EPOCH,
                None
            ),
            ParsedRange::IfRangeFailed
        ));

        /*
         * syntactically invalid (serve 200 per RFC 7233 §4.4)
         */

        assert!(matches!(
            http_parse_range(
                "bytes=1000-2000 foo",
                None,
                8192,
                HttpDate::UNIX_EPOCH,
                None
            ),
            ParsedRange::Invalid
        ));

        assert!(matches!(
            http_parse_range("bytes=foo-bar", None, 8192, HttpDate::UNIX_EPOCH, None),
            ParsedRange::Invalid
        ));

        assert!(matches!(
            http_parse_range("ABCDEFG", None, 8192, HttpDate::UNIX_EPOCH, None),
            ParsedRange::Invalid
        ));

        assert!(matches!(
            http_parse_range("bytes=", None, 8192, HttpDate::UNIX_EPOCH, None),
            ParsedRange::Invalid
        ));

        assert!(matches!(
            http_parse_range("bytes=-", None, 8192, HttpDate::UNIX_EPOCH, None),
            ParsedRange::Invalid
        ));

        // suffix length of zero is well-formed but unsatisfiable (416)
        assert!(matches!(
            http_parse_range("bytes=-0", None, 8192, HttpDate::UNIX_EPOCH, None),
            ParsedRange::NotSatisfiable
        ));

        // TODO: multi range — syntactically valid but unsupported, treat as invalid
        assert!(matches!(
            http_parse_range(
                "bytes=0-50, 100-150",
                None,
                8192,
                HttpDate::UNIX_EPOCH,
                None
            ),
            ParsedRange::Invalid
        ));
    }

    #[test]
    fn if_range_etag_test() {
        // Matching strong ETag: range applies
        assert_eq!(
            satisfiable(http_parse_range(
                "bytes=0-1023",
                Some("\"abc123\""),
                8192,
                HttpDate::UNIX_EPOCH,
                Some("\"abc123\""),
            )),
            Some(("bytes 0-1023/8192".to_string(), 0, 1024))
        );

        // Mismatched ETag: IfRangeFailed
        assert!(matches!(
            http_parse_range(
                "bytes=0-1023",
                Some("\"abc123\""),
                8192,
                HttpDate::UNIX_EPOCH,
                Some("\"different\""),
            ),
            ParsedRange::IfRangeFailed
        ));

        // No stored ETag but If-Range is an ETag: IfRangeFailed
        assert!(matches!(
            http_parse_range(
                "bytes=0-1023",
                Some("\"abc123\""),
                8192,
                HttpDate::UNIX_EPOCH,
                None
            ),
            ParsedRange::IfRangeFailed
        ));

        // Weak ETag in If-Range: IfRangeFailed (RFC 7233 §3.2)
        assert!(matches!(
            http_parse_range(
                "bytes=0-1023",
                Some("W/\"abc123\""),
                8192,
                HttpDate::UNIX_EPOCH,
                Some("\"abc123\""),
            ),
            ParsedRange::IfRangeFailed
        ));

        // Weak stored ETag with strong If-Range: IfRangeFailed
        assert!(matches!(
            http_parse_range(
                "bytes=0-1023",
                Some("\"abc123\""),
                8192,
                HttpDate::UNIX_EPOCH,
                Some("W/\"abc123\""),
            ),
            ParsedRange::IfRangeFailed
        ));
    }

    #[test]
    fn parse_content_range_test() {
        // Valid ranges
        assert_eq!(
            parse_content_range("bytes 0-499/1000"),
            Some((0, 499, 1000))
        );
        assert_eq!(
            parse_content_range("bytes 500-999/1000"),
            Some((500, 999, 1000))
        );
        assert_eq!(parse_content_range("bytes 0-0/1"), Some((0, 0, 1)));
        assert_eq!(
            parse_content_range("bytes 34744111-1071434819/1071434820"),
            Some((34_744_111, 1_071_434_819, 1_071_434_820))
        );

        // Invalid: missing prefix
        assert_eq!(parse_content_range("0-499/1000"), None);
        // Invalid: start > end
        assert_eq!(parse_content_range("bytes 500-499/1000"), None);
        // Invalid: end >= total
        assert_eq!(parse_content_range("bytes 0-1000/1000"), None);
        // Invalid: no slash
        assert_eq!(parse_content_range("bytes 0-499"), None);
        // Invalid: no dash
        assert_eq!(parse_content_range("bytes 0/1000"), None);
        // Invalid: wildcard total
        assert_eq!(parse_content_range("bytes 0-499/*"), None);
        // Invalid: empty
        assert_eq!(parse_content_range(""), None);
        // Invalid: garbage
        assert_eq!(parse_content_range("bytes abc-def/ghi"), None);
    }
}
