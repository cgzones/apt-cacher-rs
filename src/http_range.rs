use std::cmp::min;
use std::time::SystemTime;

use time::Duration;
use time::format_description::FormatItem;
use time::format_description::well_known::Rfc2822;
use time::macros::format_description;
use time::{OffsetDateTime, macros::offset};

use crate::http_etag::etag_strong_match;
use crate::warn_once_or_info;

const HTTP_DATE_FORMAT: &[FormatItem<'_>] = format_description!(
    "[weekday repr:short], [day] [month repr:short] [year] [hour]:[minute]:[second] GMT"
);

#[must_use]
pub(crate) fn systemtime_to_http_datetime(time: SystemTime) -> String {
    let odt = OffsetDateTime::from(time);
    debug_assert_eq!(odt.offset(), offset!(UTC), "offset should be UTC");

    /* round up to the next full second */
    let odt = match odt.nanosecond() {
        0 => odt,
        ns => odt.saturating_add(Duration::NANOSECOND * (1_000_000_000 - ns)),
    };
    debug_assert_eq!(
        odt.nanosecond(),
        0,
        "nanosecond should be 0 after rounding up"
    );

    odt.format(HTTP_DATE_FORMAT).expect("date should be valid")
}

#[must_use]
pub(crate) fn http_datetime_to_systemtime(time: &str) -> Option<SystemTime> {
    OffsetDateTime::parse(time, &Rfc2822)
        .ok()
        .map(std::convert::Into::into)
}

/// Format the current date and time as an HTTP date string.
#[must_use]
pub(crate) fn format_http_date() -> String {
    let now = coarsetime::Clock::now_since_epoch();
    let now = time::UtcDateTime::from_unix_timestamp_nanos(i128::from(now.as_nanos()))
        .unwrap_or_else(|_| time::UtcDateTime::now());
    systemtime_to_http_datetime(now.into())
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
pub(crate) fn cache_file_timestamp(metadata: &std::fs::Metadata) -> SystemTime {
    metadata.created().unwrap_or_else(|_err| {
        metadata
            .modified()
            .expect("Platform should support modification timestamps via setup check")
    })
}

/// Compute the HTTP `Age` header value (in seconds) for a cached file.
///
/// Uses the file's creation timestamp (or modification timestamp as fallback). Saturates to
/// `AGE_OVERFLOW_VALUE` per RFC 9111 §5.1, and returns 0 if the timestamp is somehow in the
/// future (e.g. clock skew).
#[must_use]
pub(crate) fn compute_age(metadata: &std::fs::Metadata) -> u32 {
    let ts = cache_file_timestamp(metadata);
    ts.elapsed()
        .map_or(0, |d| d.as_secs())
        .min(AGE_OVERFLOW_VALUE) as u32
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
    cache_time: SystemTime,
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
            match http_datetime_to_systemtime(if_range) {
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

    ParsedRange::Satisfiable(
        format!("bytes {start}-{end}/{file_size}"),
        start,
        content_length,
    )
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
    use std::time::{Duration, UNIX_EPOCH};

    use crate::http_range::{
        ParsedRange, http_datetime_to_systemtime, http_parse_range, parse_content_range,
        systemtime_to_http_datetime,
    };

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
            systemtime_to_http_datetime(UNIX_EPOCH),
            "Thu, 01 Jan 1970 00:00:00 GMT"
        );

        assert_eq!(
            systemtime_to_http_datetime(UNIX_EPOCH + Duration::from_secs(12_345_678_909)),
            "Tue, 21 Mar 2361 19:15:09 GMT"
        );

        assert_eq!(
            systemtime_to_http_datetime(UNIX_EPOCH + Duration::from_nanos(1)),
            "Thu, 01 Jan 1970 00:00:01 GMT"
        );

        assert_eq!(
            systemtime_to_http_datetime(UNIX_EPOCH + Duration::from_nanos(999_999_999)),
            "Thu, 01 Jan 1970 00:00:01 GMT"
        );
    }

    #[test]
    fn parse_datetime_test() {
        assert_eq!(
            http_datetime_to_systemtime("Thu, 01 Jan 1970 00:00:00 GMT"),
            Some(UNIX_EPOCH)
        );

        assert_eq!(
            http_datetime_to_systemtime("Tue, 21 Mar 2361 19:15:09 GMT"),
            Some(UNIX_EPOCH + Duration::from_secs(12_345_678_909))
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
                UNIX_EPOCH,
                None,
            )),
            Some(("bytes 0-1023/8192".to_string(), 0, 1024))
        );

        assert_eq!(
            satisfiable(http_parse_range(
                "bytes=0-1023",
                None,
                8192,
                UNIX_EPOCH,
                None
            )),
            Some(("bytes 0-1023/8192".to_string(), 0, 1024))
        );

        assert_eq!(
            satisfiable(http_parse_range(
                "bytes=5000-6999",
                None,
                10000,
                UNIX_EPOCH,
                None
            )),
            Some(("bytes 5000-6999/10000".to_string(), 5000, 2000))
        );

        assert_eq!(
            satisfiable(http_parse_range(
                "bytes=5000-6999",
                None,
                6000,
                UNIX_EPOCH,
                None
            )),
            Some(("bytes 5000-5999/6000".to_string(), 5000, 1000))
        );

        assert_eq!(
            satisfiable(http_parse_range("bytes=0-0", None, 10000, UNIX_EPOCH, None)),
            Some(("bytes 0-0/10000".to_string(), 0, 1))
        );

        assert_eq!(
            satisfiable(http_parse_range(
                "bytes=9999-9999",
                None,
                10000,
                UNIX_EPOCH,
                None
            )),
            Some(("bytes 9999-9999/10000".to_string(), 9999, 1))
        );

        assert_eq!(
            satisfiable(http_parse_range("bytes=-1", None, 10000, UNIX_EPOCH, None)),
            Some(("bytes 9999-9999/10000".to_string(), 9999, 1))
        );

        assert_eq!(
            satisfiable(http_parse_range(
                "bytes=-500",
                None,
                10000,
                UNIX_EPOCH,
                None
            )),
            Some(("bytes 9500-9999/10000".to_string(), 9500, 500))
        );

        assert_eq!(
            satisfiable(http_parse_range("bytes=-1000", None, 400, UNIX_EPOCH, None)),
            Some(("bytes 0-399/400".to_string(), 0, 400))
        );

        assert_eq!(
            satisfiable(http_parse_range(
                "bytes=4096-",
                None,
                10000,
                UNIX_EPOCH,
                None
            )),
            Some(("bytes 4096-9999/10000".to_string(), 4096, 5904))
        );

        /* stripped sub seconds */

        assert_eq!(
            satisfiable(http_parse_range(
                "bytes=0-1023",
                Some("Thu, 01 Jan 1970 00:00:01 GMT"),
                8192,
                UNIX_EPOCH + Duration::from_millis(500),
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
                UNIX_EPOCH + Duration::from_millis(500),
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
                UNIX_EPOCH,
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
                UNIX_EPOCH,
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
                UNIX_EPOCH,
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
                UNIX_EPOCH + Duration::from_secs(12_345_678_910),
                None,
            ),
            ParsedRange::IfRangeFailed
        ));

        assert!(matches!(
            http_parse_range("bytes=4000-5999", None, 3000, UNIX_EPOCH, None),
            ParsedRange::NotSatisfiable
        ));

        /* unparsable If-Range date */
        assert!(matches!(
            http_parse_range("bytes=0-1023", Some("ABCDEFG"), 8192, UNIX_EPOCH, None),
            ParsedRange::IfRangeFailed
        ));

        /*
         * syntactically invalid (serve 200 per RFC 7233 §4.4)
         */

        assert!(matches!(
            http_parse_range("bytes=1000-2000 foo", None, 8192, UNIX_EPOCH, None),
            ParsedRange::Invalid
        ));

        assert!(matches!(
            http_parse_range("bytes=foo-bar", None, 8192, UNIX_EPOCH, None),
            ParsedRange::Invalid
        ));

        assert!(matches!(
            http_parse_range("ABCDEFG", None, 8192, UNIX_EPOCH, None),
            ParsedRange::Invalid
        ));

        assert!(matches!(
            http_parse_range("bytes=", None, 8192, UNIX_EPOCH, None),
            ParsedRange::Invalid
        ));

        assert!(matches!(
            http_parse_range("bytes=-", None, 8192, UNIX_EPOCH, None),
            ParsedRange::Invalid
        ));

        // suffix length of zero is well-formed but unsatisfiable (416)
        assert!(matches!(
            http_parse_range("bytes=-0", None, 8192, UNIX_EPOCH, None),
            ParsedRange::NotSatisfiable
        ));

        // TODO: multi range — syntactically valid but unsupported, treat as invalid
        assert!(matches!(
            http_parse_range("bytes=0-50, 100-150", None, 8192, UNIX_EPOCH, None),
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
                UNIX_EPOCH,
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
                UNIX_EPOCH,
                Some("\"different\""),
            ),
            ParsedRange::IfRangeFailed
        ));

        // No stored ETag but If-Range is an ETag: IfRangeFailed
        assert!(matches!(
            http_parse_range("bytes=0-1023", Some("\"abc123\""), 8192, UNIX_EPOCH, None),
            ParsedRange::IfRangeFailed
        ));

        // Weak ETag in If-Range: IfRangeFailed (RFC 7233 §3.2)
        assert!(matches!(
            http_parse_range(
                "bytes=0-1023",
                Some("W/\"abc123\""),
                8192,
                UNIX_EPOCH,
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
                UNIX_EPOCH,
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
