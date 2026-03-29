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
    assert_eq!(
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

/// Computes the requested bytes range.
/// Returns a tuple of the formatted Content-Range header,
/// the start byte, and the total number of bytes on success.
#[must_use]
pub(crate) fn http_parse_range(
    range: &str,
    if_range: Option<&str>,
    file_size: u64,
    cache_time: SystemTime,
    file_etag: Option<&str>,
) -> Option<(String, u64, u64)> {
    if file_size == 0 {
        return None;
    }

    /* See RFC 7233 Section 2.1: https://www.rfc-editor.org/rfc/rfc7233.html#section-2.1 */

    // TODO: support multiple ranges: bytes=500-600,601-999  --  bytes=500-700,601-999

    let byte_range = range.strip_prefix("bytes=")?;
    if byte_range.contains(',') {
        warn_once_or_info!(
            "HTTP Range Request with multiple ranges are not supported (`{byte_range}`)"
        );
    }
    let (start, end) = byte_range.split_once('-')?;

    let start = if start.is_empty() {
        None
    } else {
        Some(start.parse::<u64>().ok()?)
    };
    let end = if end.is_empty() {
        None
    } else {
        Some(end.parse::<u64>().ok()?)
    };

    let (start, end) = match (start, end) {
        (None, None) => return None,
        (Some(s), Some(e)) => {
            if s > e || s >= file_size {
                return None;
            }
            (s, min(e, file_size - 1))
        }
        (Some(s), None) => {
            if s >= file_size {
                return None;
            }
            (s, file_size - 1)
        }
        (None, Some(e)) => {
            if e == 0 {
                return None;
            }
            (file_size.saturating_sub(e), file_size - 1)
        }
    };

    if let Some(if_range) = if_range {
        if if_range.starts_with('"') {
            // Strong ETag comparison
            match file_etag {
                Some(etag) if etag_strong_match(if_range, etag) => {}
                _ => return None,
            }
        } else if if_range.starts_with("W/") {
            // Weak ETags are not allowed in If-Range (RFC 7233 §3.2)
            return None;
        } else {
            let if_time = http_datetime_to_systemtime(if_range)?;
            if if_time < cache_time {
                return None;
            }
        }
    }

    Some((
        format!("bytes {start}-{end}/{file_size}"),
        start,
        end - start + 1,
    ))
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, UNIX_EPOCH};

    use crate::http_range::{
        http_datetime_to_systemtime, http_parse_range, systemtime_to_http_datetime,
    };

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
            http_parse_range(
                "bytes=0-1023",
                Some("Tue, 21 Mar 2361 19:15:09 GMT"),
                8192,
                UNIX_EPOCH,
                None,
            ),
            Some(("bytes 0-1023/8192".to_string(), 0, 1024))
        );

        assert_eq!(
            http_parse_range("bytes=0-1023", None, 8192, UNIX_EPOCH, None),
            Some(("bytes 0-1023/8192".to_string(), 0, 1024))
        );

        assert_eq!(
            http_parse_range("bytes=5000-6999", None, 10000, UNIX_EPOCH, None),
            Some(("bytes 5000-6999/10000".to_string(), 5000, 2000))
        );

        assert_eq!(
            http_parse_range("bytes=5000-6999", None, 6000, UNIX_EPOCH, None),
            Some(("bytes 5000-5999/6000".to_string(), 5000, 1000))
        );

        assert_eq!(
            http_parse_range("bytes=0-0", None, 10000, UNIX_EPOCH, None),
            Some(("bytes 0-0/10000".to_string(), 0, 1))
        );

        assert_eq!(
            http_parse_range("bytes=9999-9999", None, 10000, UNIX_EPOCH, None),
            Some(("bytes 9999-9999/10000".to_string(), 9999, 1))
        );

        assert_eq!(
            http_parse_range("bytes=-1", None, 10000, UNIX_EPOCH, None),
            Some(("bytes 9999-9999/10000".to_string(), 9999, 1))
        );

        assert_eq!(
            http_parse_range("bytes=-500", None, 10000, UNIX_EPOCH, None),
            Some(("bytes 9500-9999/10000".to_string(), 9500, 500))
        );

        assert_eq!(
            http_parse_range("bytes=-1000", None, 400, UNIX_EPOCH, None),
            Some(("bytes 0-399/400".to_string(), 0, 400))
        );

        assert_eq!(
            http_parse_range("bytes=4096-", None, 10000, UNIX_EPOCH, None),
            Some(("bytes 4096-9999/10000".to_string(), 4096, 5904))
        );

        /* stripped sub seconds */

        assert_eq!(
            http_parse_range(
                "bytes=0-1023",
                Some("Thu, 01 Jan 1970 00:00:01 GMT"),
                8192,
                UNIX_EPOCH + Duration::from_millis(500),
                None,
            ),
            Some(("bytes 0-1023/8192".to_string(), 0, 1024))
        );

        assert_eq!(
            http_parse_range(
                "bytes=0-1023",
                Some("Thu, 01 Jan 1970 00:00:00 GMT"),
                8192,
                UNIX_EPOCH + Duration::from_millis(500),
                None,
            ),
            None
        );

        /*
         * invalid
         */

        /* empty file */
        assert_eq!(
            http_parse_range(
                "bytes=0-1023",
                Some("Tue, 21 Mar 2361 19:15:09 GMT"),
                0,
                UNIX_EPOCH,
                None,
            ),
            None
        );

        /* start out-of-range */
        assert_eq!(
            http_parse_range(
                "bytes=9999-99999",
                Some("Tue, 21 Mar 2361 19:15:09 GMT"),
                8192,
                UNIX_EPOCH,
                None,
            ),
            None
        );

        /* end less than start */
        assert_eq!(
            http_parse_range(
                "bytes=1023-0",
                Some("Tue, 21 Mar 2361 19:15:09 GMT"),
                8192,
                UNIX_EPOCH,
                None,
            ),
            None
        );

        /* outdated */
        assert_eq!(
            http_parse_range(
                "bytes=0-1023",
                Some("Tue, 21 Mar 2361 19:15:09 GMT"),
                8192,
                UNIX_EPOCH + Duration::from_secs(12_345_678_910),
                None,
            ),
            None
        );

        assert_eq!(
            http_parse_range("bytes=4000-5999", None, 3000, UNIX_EPOCH, None),
            None
        );

        assert_eq!(
            http_parse_range("bytes=0-1023", Some("ABCDEFG"), 8192, UNIX_EPOCH, None),
            None
        );

        assert_eq!(
            http_parse_range("bytes=1000-2000 foo", None, 8192, UNIX_EPOCH, None),
            None
        );

        assert_eq!(
            http_parse_range("bytes=foo-bar", None, 8192, UNIX_EPOCH, None),
            None
        );

        assert_eq!(
            http_parse_range("ABCDEFG", None, 8192, UNIX_EPOCH, None),
            None
        );

        assert_eq!(
            http_parse_range("bytes=", None, 8192, UNIX_EPOCH, None),
            None
        );

        assert_eq!(
            http_parse_range("bytes=-", None, 8192, UNIX_EPOCH, None),
            None
        );

        assert_eq!(
            http_parse_range("bytes=-0", None, 8192, UNIX_EPOCH, None),
            None
        );

        // TODO: multi range
        assert_eq!(
            http_parse_range("bytes=0-50, 100-150", None, 8192, UNIX_EPOCH, None),
            None
        );
    }

    #[test]
    fn if_range_etag_test() {
        // Matching strong ETag: range applies
        assert_eq!(
            http_parse_range(
                "bytes=0-1023",
                Some("\"abc123\""),
                8192,
                UNIX_EPOCH,
                Some("\"abc123\""),
            ),
            Some(("bytes 0-1023/8192".to_string(), 0, 1024))
        );

        // Mismatched ETag: range does not apply
        assert_eq!(
            http_parse_range(
                "bytes=0-1023",
                Some("\"abc123\""),
                8192,
                UNIX_EPOCH,
                Some("\"different\""),
            ),
            None
        );

        // No stored ETag but If-Range is an ETag: range does not apply
        assert_eq!(
            http_parse_range("bytes=0-1023", Some("\"abc123\""), 8192, UNIX_EPOCH, None,),
            None
        );

        // Weak ETag in If-Range: range does not apply (RFC 7233 §3.2)
        assert_eq!(
            http_parse_range(
                "bytes=0-1023",
                Some("W/\"abc123\""),
                8192,
                UNIX_EPOCH,
                Some("\"abc123\""),
            ),
            None
        );

        // Weak stored ETag with strong If-Range: range does not apply
        assert_eq!(
            http_parse_range(
                "bytes=0-1023",
                Some("\"abc123\""),
                8192,
                UNIX_EPOCH,
                Some("W/\"abc123\""),
            ),
            None
        );
    }
}
