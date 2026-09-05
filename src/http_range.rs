use std::cmp::min;
use std::num::NonZero;
use std::sync::{Arc, LazyLock};
use std::time::{SystemTime, SystemTimeError};

use parking_lot::RwLock;
use time::format_description::FormatItem;
use time::format_description::well_known::Rfc2822;
use time::macros::format_description;
use time::{OffsetDateTime, macros::offset};

use crate::http_etag::etag_strong_match;
use crate::{swrite, warn_once_or_info};

const HTTP_DATE_FORMAT: &[FormatItem<'_>] = format_description!(
    "[weekday repr:short], [day] [month repr:short] [year] [hour]:[minute]:[second] GMT"
);

/// A wall-clock point in time at HTTP-date (1-second) granularity.
///
/// HTTP date headers (RFC 9110 §5.6.7, IMF-fixdate) encode whole seconds since the
/// Unix epoch, so this is the natural precision for `Last-Modified`, `If-Range`,
/// `If-Modified-Since`, and the `Date` header.
///
/// All constructors clamp the stored value to [`Self::MAX_SECS`], the last instant
/// `OffsetDateTime` can represent, which is what makes [`HttpDate::format`]
/// total: a filesystem reporting an absurd `st_mtime`/`st_btime` (the values
/// reaching [`cache_file_http_date`]) yields the clamped date instead of
/// panicking inside the formatter.
///
/// The current value is read via [`HttpDate::now`], which uses
/// `coarsetime::Clock::now_since_epoch()` (`CLOCK_REALTIME_COARSE` on Linux — a
/// jiffy-updated read, much cheaper than `SystemTime::now()`).
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct HttpDate(u64);

impl HttpDate {
    pub(crate) const UNIX_EPOCH: Self = Self(0);

    /// Inclusive upper bound on the stored seconds value: `9999-12-31
    /// 23:59:59 UTC`, the largest instant `OffsetDateTime` accepts from
    /// `from_unix_timestamp` (the `time` crate's `large-dates` feature, which
    /// would widen it, is off).  Clamping every constructor here is what lets
    /// [`HttpDate::format`] `expect` both the `i64` conversion and the
    /// `OffsetDateTime` construction.
    const MAX_SECS: u64 = 253_402_300_799;

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
    fn elapsed_secs(self) -> Option<u64> {
        Self::now().0.checked_sub(self.0)
    }

    /// Format as an IMF-fixdate string (e.g. `Sun, 06 Nov 1994 08:49:37 GMT`).
    #[must_use]
    pub(crate) fn format(self) -> String {
        let secs_i64 = i64::try_from(self.0).expect("HttpDate is clamped to MAX_SECS");
        let odt = OffsetDateTime::from_unix_timestamp(secs_i64)
            .expect("MAX_SECS is the last instant OffsetDateTime represents");
        debug_assert_eq!(odt.offset(), offset!(UTC), "offset should be UTC");
        odt.format(HTTP_DATE_FORMAT).expect("date should be valid")
    }

    /// Parse an RFC 2822 / IMF-fixdate string. Returns `None` for malformed input
    /// or dates before the Unix epoch.
    #[must_use]
    pub(crate) fn parse(s: &str) -> Option<Self> {
        let odt = OffsetDateTime::parse(s, &Rfc2822).ok()?;
        u64::try_from(odt.unix_timestamp()).ok().map(Self::clamped)
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
/// Cached at 1-second granularity.  Every response writer calls this once
/// per response for the `Date` header, so the steady state is a shared
/// read lock plus an `Arc` refcount bump — no allocation and no exclusive
/// lock; only the once-per-second rollover takes the write lock and
/// formats.
#[must_use]
pub(crate) fn format_http_date() -> Arc<str> {
    static CACHE: LazyLock<RwLock<(HttpDate, Arc<str>)>> = LazyLock::new(|| {
        let now = HttpDate::now();
        RwLock::new((now, now.format().into()))
    });

    let now = HttpDate::now();

    {
        let cached = CACHE.read();
        if cached.0 == now {
            return Arc::clone(&cached.1);
        }
    }

    let formatted: Arc<str> = now.format().into();

    let mut cached = CACHE.write();
    if cached.0 != now {
        cached.0 = now;
        cached.1 = Arc::clone(&formatted);
    }

    formatted
}

/// Maximum value for the HTTP `Age` header, per RFC 9111 §5.1: a cache
/// receiving a value greater than the greatest integer it can represent, or
/// overflowing an age calculation, must transmit an `Age` of 2147483648
/// (2^31).
const AGE_OVERFLOW_VALUE: u64 = 1u64 << 31;

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
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ParsedRange {
    /// Valid, satisfiable range: Content-Range header value, start byte, content length.
    Satisfiable(String, u64, u64),
    /// The Range header is syntactically malformed. Per RFC 9110 §14.2, the recipient
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
    /* See RFC 9110 Section 14.1.1: https://www.rfc-editor.org/rfc/rfc9110.html#section-14.1.1 */

    // TODO: support multiple ranges: bytes=500-600,601-999  --  bytes=500-700,601-999

    let Some(byte_range) = range.strip_prefix("bytes=") else {
        return ParsedRange::Invalid;
    };
    if byte_range.contains(',') {
        warn_once_or_info!(
            "HTTP Range requests with multiple ranges are not supported (`{}`); ignoring the header and serving the full file",
            byte_range.escape_debug()
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

    // A zero-length entity admits no satisfiable byte range (RFC 9110
    // §14.1.2: a valid range requires start < current length, impossible at
    // length zero); the arms below all yield `NotSatisfiable` for it.
    // Syntactic invalidity is checked first so a malformed range is ignored
    // (served as 200) regardless of file size, per RFC 9110 §14.2.
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
            // A zero suffix-length is unsatisfiable, and so is any suffix
            // of a zero-length file.
            if e == 0 || file_size == 0 {
                return ParsedRange::NotSatisfiable;
            }
            (file_size.saturating_sub(e), file_size - 1)
        }
    };

    if let Some(if_range) = if_range
        && !if_range_matches(if_range, cache_time, file_etag)
    {
        return ParsedRange::IfRangeFailed;
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
    swrite!(content_range, "bytes {start}-{end}/{file_size}");
    ParsedRange::Satisfiable(content_range, start, content_length)
}

/// Evaluate an `If-Range` precondition (RFC 9110 §13.1.5) against the
/// representation a `Range` would be cut from.
///
/// An entity-tag condition must be a *strong* comparison against the stored
/// `ETag`; a weak tag on either side never matches, because a weak validator
/// says nothing about byte-for-byte identity.  An HTTP-date condition must
/// match `cache_time` *exactly*, not merely be no older: a client holding a
/// validator we cannot reproduce (e.g. the file-birth-time fallback) fails
/// the condition and gets a safe full 200 instead of risking a 206 stitched
/// onto bytes from a different revision.  An unparsable date fails too.
#[must_use]
fn if_range_matches(if_range: &str, cache_time: HttpDate, file_etag: Option<&str>) -> bool {
    if if_range.starts_with('"') {
        return matches!(file_etag, Some(etag) if etag_strong_match(if_range, etag));
    }
    if if_range.starts_with("W/") {
        return false;
    }
    HttpDate::parse(if_range).is_some_and(|if_time| if_time == cache_time)
}

/// A parsed `Content-Range: bytes <start>-<end>/<total>` response header.
///
/// [`parse_content_range`] is the only constructor and it rejects everything
/// but `start <= end < total`.  Those bounds are what make [`Self::total`]
/// and [`Self::span`] `NonZero` and [`Self::runs_to_end`] wrap-free.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ContentRange {
    start: u64,
    end: u64,
    total: NonZero<u64>,
}

impl ContentRange {
    /// First byte of the range.
    #[must_use]
    pub(crate) const fn start(self) -> u64 {
        self.start
    }

    /// Size of the whole representation the range was cut from.
    #[must_use]
    pub(crate) const fn total(self) -> NonZero<u64> {
        self.total
    }

    /// Number of bytes the range covers (`end - start + 1`).
    #[must_use]
    pub(crate) fn span(self) -> NonZero<u64> {
        NonZero::<u64>::MIN.saturating_add(self.end - self.start)
    }

    /// Whether the range ends on the representation's last byte.
    #[must_use]
    pub(crate) const fn runs_to_end(self) -> bool {
        self.total.get() - self.end == 1
    }
}

/// Parse an HTTP `Content-Range` response header value.
///
/// Expects the complete `bytes {start}-{end}/{total}` form; the `*`
/// unsatisfied-range and unknown-total spellings and any inconsistent
/// bounds yield `None`.
#[must_use]
pub(crate) fn parse_content_range(value: &str) -> Option<ContentRange> {
    let rest = value.strip_prefix("bytes ")?;
    let (range_part, total_str) = rest.split_once('/')?;
    let (start_str, end_str) = range_part.split_once('-')?;

    let start = start_str.parse::<u64>().ok()?;
    let end = end_str.parse::<u64>().ok()?;
    let total = total_str.parse::<u64>().ok()?;

    if start > end || end >= total {
        return None;
    }

    Some(ContentRange {
        start,
        end,
        // `end >= total` was rejected above, so `total` is at least 1.
        total: NonZero::new(total)?,
    })
}

#[cfg(test)]
mod tests {
    use std::num::NonZero;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use crate::http_range::{
        ContentRange, HttpDate, ParsedRange, http_parse_range, if_range_matches,
        parse_content_range,
    };

    /// Helper to unwrap a `ParsedRange::Satisfiable` for concise test assertions.
    fn satisfiable(r: ParsedRange) -> Option<(String, u64, u64)> {
        match r {
            ParsedRange::Satisfiable(cr, s, l) => Some((cr, s, l)),
            ParsedRange::Invalid | ParsedRange::NotSatisfiable | ParsedRange::IfRangeFailed => None,
        }
    }

    /// The expected parse of a `bytes start-end/total` value.
    fn content_range(start: u64, end: u64, total: u64) -> ContentRange {
        ContentRange {
            start,
            end,
            total: NonZero::new(total).unwrap(),
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

        // Pre-epoch dates parse as an HTTP-date but have no `HttpDate`.
        assert_eq!(HttpDate::parse("Wed, 31 Dec 1969 23:59:59 GMT"), None);
        // Trailing junk is not silently accepted.
        assert_eq!(HttpDate::parse("Thu, 01 Jan 1970 00:00:00 GMT junk"), None);
        // The two obsolete HTTP-date spellings RFC 9110 section 5.6.7 still
        // requires *recipients* to accept are rejected here; see
        // `http_last_modified::is_valid_http_date`.
        assert_eq!(HttpDate::parse("Sunday, 06-Nov-94 08:49:37 GMT"), None);
        assert_eq!(HttpDate::parse("Sun Nov  6 08:49:37 1994"), None);
    }

    #[test]
    fn clamps_to_max_representable_date() {
        // An out-of-range seconds value must clamp so that `format` is total:
        // both the i64 cast and `OffsetDateTime::from_unix_timestamp` inside
        // it are infallible only because of this.
        assert_eq!(
            HttpDate::from_secs(u64::MAX),
            HttpDate::from_secs(u64::MAX - 1),
            "values above MAX_SECS must saturate to the same clamped HttpDate"
        );
        assert_eq!(
            HttpDate::from_secs(u64::MAX).format(),
            "Fri, 31 Dec 9999 23:59:59 GMT"
        );
        // A filesystem reporting an absurd birth/modification time reaches
        // `format` through `cache_file_http_date`; it must clamp, not panic.
        assert_eq!(
            HttpDate::from(SystemTime::UNIX_EPOCH + Duration::from_secs(300_000_000_001)).format(),
            "Fri, 31 Dec 9999 23:59:59 GMT"
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

        /* If-Range date matching the cache time exactly (RFC 9110 §13.1.5) */
        assert_eq!(
            satisfiable(http_parse_range(
                "bytes=0-1023",
                Some("Thu, 01 Jan 1970 00:00:00 GMT"),
                8192,
                HttpDate::UNIX_EPOCH,
                None,
            )),
            Some(("bytes 0-1023/8192".to_string(), 0, 1024))
        );

        /* If-Range time newer than cache time: exact match required, IfRangeFailed */
        assert!(matches!(
            http_parse_range(
                "bytes=0-1023",
                Some("Tue, 21 Mar 2361 19:15:09 GMT"),
                8192,
                HttpDate::UNIX_EPOCH,
                None,
            ),
            ParsedRange::IfRangeFailed
        ));

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

        /* empty file, open-ended and suffix forms */
        assert!(matches!(
            http_parse_range("bytes=0-", None, 0, HttpDate::UNIX_EPOCH, None),
            ParsedRange::NotSatisfiable
        ));
        assert!(matches!(
            http_parse_range("bytes=-500", None, 0, HttpDate::UNIX_EPOCH, None),
            ParsedRange::NotSatisfiable
        ));

        /* empty file with a *malformed* range: ignored (200), not 416, per RFC 9110 §14.2 */
        assert!(matches!(
            http_parse_range("bytes=5-2", None, 0, HttpDate::UNIX_EPOCH, None),
            ParsedRange::Invalid
        ));
        assert!(matches!(
            http_parse_range("bytes=-", None, 0, HttpDate::UNIX_EPOCH, None),
            ParsedRange::Invalid
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

        /* end less than start: syntactically invalid, ignore per RFC 9110 §14.2 */
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
         * syntactically invalid (serve 200 per RFC 9110 §14.2)
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
        assert!(matches!(
            http_parse_range("bytes=0-50,100-150", None, 8192, HttpDate::UNIX_EPOCH, None),
            ParsedRange::Invalid
        ));
    }

    #[test]
    fn http_parse_range_numeric_edges() {
        // Byte positions that do not fit in u64 are malformed, not
        // unsatisfiable: ignore the header and serve the full entity.
        for range in [
            "bytes=18446744073709551616-",
            "bytes=0-18446744073709551616",
            "bytes=-18446744073709551616",
            // A negative first-byte-pos splits into an empty start and a
            // non-numeric suffix-length.
            "bytes=-1-2",
        ] {
            assert_eq!(
                http_parse_range(range, None, 100, HttpDate::UNIX_EPOCH, None),
                ParsedRange::Invalid,
                "range {range}"
            );
        }

        // `u64::MAX` itself parses; a last-byte-pos past the end clamps to the
        // final byte instead of failing.
        assert_eq!(
            satisfiable(http_parse_range(
                "bytes=0-18446744073709551615",
                None,
                100,
                HttpDate::UNIX_EPOCH,
                None
            )),
            Some(("bytes 0-99/100".to_string(), 0, 100))
        );
        // A suffix-length longer than the file yields the whole file.
        assert_eq!(
            satisfiable(http_parse_range(
                "bytes=-18446744073709551615",
                None,
                100,
                HttpDate::UNIX_EPOCH,
                None
            )),
            Some(("bytes 0-99/100".to_string(), 0, 100))
        );
        // A first-byte-pos past the end is unsatisfiable, however large.
        assert_eq!(
            http_parse_range(
                "bytes=18446744073709551615-",
                None,
                100,
                HttpDate::UNIX_EPOCH,
                None
            ),
            ParsedRange::NotSatisfiable
        );
    }

    #[test]
    fn if_range_matches_table() {
        let epoch = HttpDate::UNIX_EPOCH;

        // A strong entity-tag on both sides, byte-identical: the only match.
        assert!(if_range_matches("\"abc\"", epoch, Some("\"abc\"")));
        assert!(!if_range_matches("\"abc\"", epoch, Some("\"other\"")));
        assert!(!if_range_matches("\"abc\"", epoch, None));
        // A weak tag on either side never matches (RFC 9110 section 13.1.5).
        assert!(!if_range_matches("W/\"abc\"", epoch, Some("\"abc\"")));
        assert!(!if_range_matches("\"abc\"", epoch, Some("W/\"abc\"")));

        // Anything not spelled as an entity-tag is read as an HTTP-date and
        // must match the representation's timestamp exactly; the stored ETag
        // plays no part.
        assert!(if_range_matches(
            "Thu, 01 Jan 1970 00:00:00 GMT",
            epoch,
            Some("\"abc\"")
        ));
        assert!(!if_range_matches(
            "Thu, 01 Jan 1970 00:00:01 GMT",
            epoch,
            None
        ));
        assert!(!if_range_matches("not-a-date", epoch, Some("\"abc\"")));
        assert!(!if_range_matches("", epoch, Some("\"abc\"")));
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

        // Weak ETag in If-Range: IfRangeFailed (RFC 9110 §13.1.5)
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
            Some(content_range(0, 499, 1000))
        );
        assert_eq!(
            parse_content_range("bytes 500-999/1000"),
            Some(content_range(500, 999, 1000))
        );
        assert_eq!(
            parse_content_range("bytes 0-0/1"),
            Some(content_range(0, 0, 1))
        );
        assert_eq!(
            parse_content_range("bytes 34744111-1071434819/1071434820"),
            Some(content_range(34_744_111, 1_071_434_819, 1_071_434_820))
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

    #[test]
    fn parse_content_range_accepts_boundary() {
        // The boundary case: start=0, end=u64::MAX-1, total=u64::MAX.
        // start <= end, end < total, end - start + 1 = u64::MAX (fits in u64).
        let s = format!("bytes 0-{}/{}", u64::MAX - 1, u64::MAX);
        let parsed = parse_content_range(&s).expect("consistent bounds");
        assert_eq!(parsed.start(), 0);
        assert_eq!(parsed.total().get(), u64::MAX);
        assert_eq!(parsed.span().get(), u64::MAX);
        assert!(parsed.runs_to_end());
    }

    #[test]
    fn content_range_derives_span_and_tail() {
        // A middle slice: the span is inclusive of both ends and the range
        // stops short of the last byte.
        let middle = parse_content_range("bytes 40-98/100").expect("consistent bounds");
        assert_eq!(middle.start(), 40);
        assert_eq!(middle.total().get(), 100);
        assert_eq!(middle.span().get(), 59);
        assert!(!middle.runs_to_end());

        // The remainder of the object, as a resume answer delivers it.
        let tail = parse_content_range("bytes 40-99/100").expect("consistent bounds");
        assert_eq!(tail.span().get(), 60);
        assert!(tail.runs_to_end());

        // A single-byte tail is still a span of one.
        let last = parse_content_range("bytes 99-99/100").expect("consistent bounds");
        assert_eq!(last.span().get(), 1);
        assert!(last.runs_to_end());
    }

    #[test]
    fn parse_content_range_rejects_total_smaller_than_end() {
        // total < end -> inconsistent Content-Range, must be rejected.
        assert!(parse_content_range("bytes 100-200/50").is_none());
    }

    #[test]
    fn http_parse_range_rejects_inverted_range() {
        let result = http_parse_range(
            "bytes=500-100",
            None,
            1_000_000,
            HttpDate::from_secs(0),
            None,
        );
        assert!(matches!(result, ParsedRange::Invalid));
    }

    #[test]
    fn http_parse_range_zero_file_size_returns_not_satisfiable() {
        let result = http_parse_range("bytes=0-100", None, 0, HttpDate::from_secs(0), None);
        assert!(matches!(result, ParsedRange::NotSatisfiable));
    }
}
