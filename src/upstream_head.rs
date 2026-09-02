//! Backend-neutral classification of an upstream response head.
//!
//! `hyper_conn.rs::serve_new_file` and `splice/mod.rs::splice_proxy_drive`
//! fetch the same upstream resources and must reach the same decisions on the
//! (status, resume state, `Content-Range`, `Content-Length`, cached flavor)
//! truth table: 304 revalidation, non-2xx relay, resume anomalies, the
//! unsolicited-206 cache-poisoning guard, the `max_object_size` cap and
//! missing body framing.  Each backend used to hand-write that table, and the
//! 502 bodies and precedence had drifted.  This module owns the table once.
//!
//! - [`UpstreamHead`] is the projection of a response head the table reads:
//!   status, the length-delimited `Content-Length` (already resolved against
//!   chunked framing, RFC 9112 section 6.1) and the parsed `Content-Range`.
//!   Constructors: [`UpstreamHead::from_response`] for hyper's
//!   `http::Response` and `splice::http::UpstreamResponse::head` for splice's
//!   httparse-based parser.  Validator and metadata headers (`ETag`,
//!   `Last-Modified`, `Content-Type`) are deliberately absent: no shared
//!   decision reads them and each backend validates them on its own schedule.
//! - [`plan_download`] and [`plan_fresh_download`] are pure: no I/O, no
//!   `global_config()`, no metric bumps, no logging.  The backends own how to
//!   discard a partial, how to re-fetch, how to write the 502 and the log
//!   line, and bump metrics through [`RejectReason::record_metrics`].
//! - The 502 bodies are consts behind [`RejectReason::body`].
//!
//! Backend contract: call [`plan_download`] once with the resume state.
//! `Err(`[`ResumeAnomaly`]`)` means "discard the partial file"; then either
//! re-plan the same head (a 200 that ignored `Range` is a usable fresh body)
//! or re-fetch without `Range` and plan the new head, both through
//! [`plan_fresh_download`], which cannot fail.  The stale cached copy a
//! conditional request was sent for travels through the planner as the
//! generic `C` and comes back only inside [`DownloadPlan::NotModified`], so
//! neither backend has to write a "304 without a cached copy" arm.

use std::num::NonZero;

use http::StatusCode;

use crate::{
    ContentLength, VOLATILE_UNKNOWN_CONTENT_LENGTH_UPPER, cache_layout::CachedFlavor, limits,
    metrics,
};

/// The part of an upstream response head the download decision reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct UpstreamHead {
    pub(crate) status: StatusCode,
    /// Declared body length of a length-delimited response.  `None` when the
    /// header is absent or unparsable, or when `Transfer-Encoding: chunked`
    /// overrides it (RFC 9112 section 6.1; a `Content-Length` sent alongside
    /// chunked framing is a smuggling signal and must be ignored).
    pub(crate) content_length: Option<u64>,
    /// Parsed `Content-Range` as `(start, end, total)` with
    /// `start <= end < total` guaranteed by `http_range::parse_content_range`;
    /// `None` when absent or malformed.
    pub(crate) content_range: Option<(u64, u64, u64)>,
}

#[cfg(feature = "hyper")]
impl UpstreamHead {
    /// Project a hyper response.  The body type is irrelevant; only the
    /// status and headers are read.
    #[must_use]
    pub(crate) fn from_response<B>(response: &http::Response<B>) -> Self {
        use http::header::{CONTENT_LENGTH, CONTENT_RANGE, TRANSFER_ENCODING};

        let headers = response.headers();

        let chunked = headers.get_all(TRANSFER_ENCODING).iter().any(|hv| {
            hv.to_str().is_ok_and(|s| {
                s.split(',')
                    .any(|v| v.trim().eq_ignore_ascii_case("chunked"))
            })
        });
        let content_length = if chunked {
            None
        } else {
            headers
                .get(CONTENT_LENGTH)
                .and_then(|hv| hv.to_str().ok())
                .and_then(|s| s.trim().parse::<u64>().ok())
        };
        let content_range = headers
            .get(CONTENT_RANGE)
            .and_then(|hv| hv.to_str().ok())
            .and_then(crate::http_range::parse_content_range);

        Self {
            status: response.status(),
            content_length,
            content_range,
        }
    }
}

/// A partial download the upstream request asked to resume (`Range:
/// bytes=<offset>-` plus `If-Range`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ResumeState {
    /// Bytes already on disk; the requested range starts here.
    pub(crate) offset: NonZero<u64>,
    /// Total size recorded when the partial was started, if the xattr
    /// survived; a 206 whose `Content-Range` total differs means the upstream
    /// file was replaced.
    pub(crate) expected_total: Option<u64>,
}

impl ResumeState {
    /// `None` for `offset == 0`: nothing to resume, the request was sent
    /// without `Range`.
    #[must_use]
    pub(crate) fn new(offset: u64, expected_total: Option<u64>) -> Option<Self> {
        NonZero::new(offset).map(|offset| Self {
            offset,
            expected_total,
        })
    }
}

/// Why a resumed request cannot continue from the partial file.  Every
/// variant means "discard the partial"; [`ResumeAnomaly::needs_refetch`]
/// says whether the response at hand is still a usable fresh body.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ResumeAnomaly {
    /// The upstream ignored `Range` and answered 200 with the whole file.
    /// The response is a valid fresh download: re-plan the same head with
    /// no resume state.
    RangeIgnored,
    /// 416: the partial is stale.  Re-fetch without `Range`.
    RangeNotSatisfiable,
    /// 206 whose `Content-Range` is missing, malformed, does not start at the
    /// resume offset, does not run to the end of the file, or reports a total
    /// other than the one the partial was started with.  The stored bytes
    /// cannot be appended to; re-fetch without `Range`.
    ContentRangeMismatch,
}

impl ResumeAnomaly {
    /// Whether the backend must send a new unconditional request.  `false`
    /// only for [`ResumeAnomaly::RangeIgnored`], whose 200 body is used as is.
    #[must_use]
    pub(crate) const fn needs_refetch(self) -> bool {
        match self {
            Self::RangeIgnored => false,
            Self::RangeNotSatisfiable | Self::ContentRangeMismatch => true,
        }
    }
}

/// An upstream response the proxy refuses to relay or cache, answered with
/// 502 and [`RejectReason::body`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RejectReason {
    /// 206 for a request sent without `Range`.  Treating it as a 200 would
    /// write the partial bytes at offset 0 and mark the file complete at the
    /// partial length: a cache-poisoning vector.
    Unsolicited206,
    /// A resumed 206 whose `Content-Length` disagrees with the byte span its
    /// `Content-Range` declares.
    InconsistentContentRange { content_length: u64, span: u64 },
    /// The declared total (`Content-Length`, or the `Content-Range` total of
    /// a resumed 206) exceeds `max_object_size`.
    Oversize { total: u64 },
    /// A permanent file whose body framing is unknown (no `Content-Length`,
    /// chunked or close-delimited).  Volatile files stream or buffer such
    /// bodies instead.
    NoContentLength,
    /// `Content-Length: 0`: the cache cannot hold an empty object.
    ZeroContentLength,
}

impl RejectReason {
    /// The 502 response body.  One string per condition across all backends.
    #[must_use]
    pub(crate) const fn body(self) -> &'static str {
        match self {
            Self::Unsolicited206 => "Unsolicited 206",
            Self::InconsistentContentRange { .. } => "Inconsistent Content-Range",
            Self::Oversize { .. } => "Upstream resource too large",
            Self::NoContentLength => "no Content-Length",
            Self::ZeroContentLength => "Zero Content-Length",
        }
    }

    /// Bump the counters this rejection is accounted under.  Called once by
    /// the backend when it emits the 502.
    pub(crate) fn record_metrics(self) {
        match self {
            Self::Unsolicited206 => {
                metrics::UPSTREAM_PROTOCOL_VIOLATION.increment();
                metrics::UPSTREAM_UNSOLICITED_206.increment();
            }
            Self::InconsistentContentRange { .. }
            | Self::NoContentLength
            | Self::ZeroContentLength => {
                metrics::UPSTREAM_PROTOCOL_VIOLATION.increment();
            }
            Self::Oversize { .. } => {
                metrics::DOWNLOAD_REJECTED_OVERSIZE.increment();
            }
        }
    }
}

/// What to do with an upstream response.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum DownloadPlan<C> {
    /// 304 for a revalidating volatile: refresh the cached copy's mtime and
    /// serve it.  Carries the cached-copy evidence the caller passed in.
    NotModified(C),
    /// Not a cacheable body (any status other than 200/206, or a 304 with no
    /// cached copy to serve): relay status, headers and body to the client.
    Passthrough,
    /// Answer 502 with [`RejectReason::body`] and record
    /// [`RejectReason::record_metrics`].
    Reject(RejectReason),
    /// Cache and serve the body.  `total` is the whole object, `body` the
    /// bytes on the wire (they differ only on a resume), `resume_offset` the
    /// bytes already on disk.  `ContentLength::Unknown` only occurs for
    /// volatile files without a `Content-Length`.
    Download {
        total: ContentLength,
        body: ContentLength,
        resume_offset: u64,
    },
}

/// Classify an upstream response.
///
/// `cached` is the stale cached copy a conditional request was sent for
/// (volatile revalidation); `Some` makes a 304 serve it, `None` relays a 304
/// like any other non-2xx.  `resume` is the partial a `Range` request was
/// sent for (permanent files); the two are mutually exclusive by
/// construction.
///
/// `Err` reports a resume anomaly: discard the partial, then re-plan through
/// [`plan_fresh_download`] (see [`ResumeAnomaly::needs_refetch`]).
pub(crate) fn plan_download<C>(
    head: &UpstreamHead,
    resume: Option<ResumeState>,
    flavor: CachedFlavor,
    cached: Option<C>,
    max_object_size: Option<NonZero<u64>>,
) -> Result<DownloadPlan<C>, ResumeAnomaly> {
    debug_assert!(
        resume.is_none() || cached.is_none(),
        "a request resumes a permanent partial or revalidates a volatile copy, never both"
    );

    let Some(resume) = resume else {
        return Ok(plan_fresh_download(head, flavor, cached, max_object_size));
    };

    match head.status {
        StatusCode::OK => Err(ResumeAnomaly::RangeIgnored),
        StatusCode::RANGE_NOT_SATISFIABLE => Err(ResumeAnomaly::RangeNotSatisfiable),
        StatusCode::PARTIAL_CONTENT => plan_resumed_206(head, resume, max_object_size),
        // 3xx/4xx/5xx: relayed like on a fresh request; the partial is kept
        // for the next attempt.
        _ => Ok(plan_fresh_download(head, flavor, cached, max_object_size)),
    }
}

/// A resumed request answered with 206: accept only a response delivering
/// exactly the remainder of the object the partial was started from.
fn plan_resumed_206<C>(
    head: &UpstreamHead,
    resume: ResumeState,
    max_object_size: Option<NonZero<u64>>,
) -> Result<DownloadPlan<C>, ResumeAnomaly> {
    let Some((start, end, _total)) = head.content_range.filter(|&(start, end, total)| {
        start == resume.offset.get()
            && end.checked_add(1) == Some(total)
            && resume
                .expected_total
                .is_none_or(|expected| expected == total)
    }) else {
        return Err(ResumeAnomaly::ContentRangeMismatch);
    };

    // `parse_content_range` guarantees `start <= end < total`, so both the
    // total and the remaining span are at least 1.
    let total = NonZero::<u64>::MIN.saturating_add(end);
    let span = NonZero::<u64>::MIN.saturating_add(end - start);

    if let Some(content_length) = head.content_length
        && content_length != span.get()
    {
        return Ok(DownloadPlan::Reject(
            RejectReason::InconsistentContentRange {
                content_length,
                span: span.get(),
            },
        ));
    }

    if !limits::content_length_within_cap(total.get(), max_object_size) {
        return Ok(DownloadPlan::Reject(RejectReason::Oversize {
            total: total.get(),
        }));
    }

    Ok(DownloadPlan::Download {
        total: ContentLength::Exact(total),
        body: ContentLength::Exact(span),
        resume_offset: start,
    })
}

/// Classify a response to a request sent without `Range`: the initial
/// request of a non-resuming download, the re-fetch after a resume anomaly,
/// or the same 200 head re-planned after the upstream ignored `Range`.
pub(crate) fn plan_fresh_download<C>(
    head: &UpstreamHead,
    flavor: CachedFlavor,
    cached: Option<C>,
    max_object_size: Option<NonZero<u64>>,
) -> DownloadPlan<C> {
    if head.status == StatusCode::NOT_MODIFIED
        && let Some(cached) = cached
    {
        return DownloadPlan::NotModified(cached);
    }

    if head.status == StatusCode::PARTIAL_CONTENT {
        return DownloadPlan::Reject(RejectReason::Unsolicited206);
    }

    if head.status != StatusCode::OK {
        return DownloadPlan::Passthrough;
    }

    let Some(content_length) = head.content_length else {
        return match flavor {
            CachedFlavor::Volatile => DownloadPlan::Download {
                total: ContentLength::Unknown(VOLATILE_UNKNOWN_CONTENT_LENGTH_UPPER),
                body: ContentLength::Unknown(VOLATILE_UNKNOWN_CONTENT_LENGTH_UPPER),
                resume_offset: 0,
            },
            CachedFlavor::Permanent => DownloadPlan::Reject(RejectReason::NoContentLength),
        };
    };

    let Some(content_length) = NonZero::new(content_length) else {
        return DownloadPlan::Reject(RejectReason::ZeroContentLength);
    };

    if !limits::content_length_within_cap(content_length.get(), max_object_size) {
        return DownloadPlan::Reject(RejectReason::Oversize {
            total: content_length.get(),
        });
    }

    DownloadPlan::Download {
        total: ContentLength::Exact(content_length),
        body: ContentLength::Exact(content_length),
        resume_offset: 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nonzero;

    /// Marker for the cached-copy evidence in tests.
    #[derive(Debug, PartialEq, Eq)]
    struct Cached;

    const NO_CAP: Option<NonZero<u64>> = None;

    fn head(status: u16, content_length: Option<u64>, content_range: Option<&str>) -> UpstreamHead {
        UpstreamHead {
            status: StatusCode::from_u16(status).unwrap(),
            content_length,
            content_range: content_range.and_then(crate::http_range::parse_content_range),
        }
    }

    fn fresh(
        head: &UpstreamHead,
        flavor: CachedFlavor,
        cached: Option<Cached>,
        cap: Option<NonZero<u64>>,
    ) -> DownloadPlan<Cached> {
        plan_download(head, None, flavor, cached, cap).unwrap()
    }

    fn resumed(
        head: &UpstreamHead,
        offset: u64,
        expected_total: Option<u64>,
        cap: Option<NonZero<u64>>,
    ) -> Result<DownloadPlan<Cached>, ResumeAnomaly> {
        plan_download(
            head,
            ResumeState::new(offset, expected_total),
            CachedFlavor::Permanent,
            None,
            cap,
        )
    }

    fn exact_download(total: u64, body: u64, resume_offset: u64) -> DownloadPlan<Cached> {
        DownloadPlan::Download {
            total: ContentLength::Exact(NonZero::new(total).unwrap()),
            body: ContentLength::Exact(NonZero::new(body).unwrap()),
            resume_offset,
        }
    }

    #[test]
    fn resume_state_zero_offset_is_none() {
        assert_eq!(ResumeState::new(0, Some(10)), None);
        assert_eq!(
            ResumeState::new(5, Some(10)),
            Some(ResumeState {
                offset: nonzero!(5),
                expected_total: Some(10),
            })
        );
    }

    #[test]
    fn fresh_200_with_content_length_downloads() {
        let h = head(200, Some(1234), None);
        assert_eq!(
            fresh(&h, CachedFlavor::Permanent, None, NO_CAP),
            exact_download(1234, 1234, 0)
        );
        assert_eq!(
            fresh(&h, CachedFlavor::Volatile, Some(Cached), NO_CAP),
            exact_download(1234, 1234, 0)
        );
    }

    #[test]
    fn fresh_200_at_cap_downloads_and_above_cap_rejects() {
        let cap = Some(nonzero!(1234));
        assert_eq!(
            fresh(
                &head(200, Some(1234), None),
                CachedFlavor::Permanent,
                None,
                cap
            ),
            exact_download(1234, 1234, 0)
        );
        assert_eq!(
            fresh(
                &head(200, Some(1235), None),
                CachedFlavor::Permanent,
                None,
                cap
            ),
            DownloadPlan::Reject(RejectReason::Oversize { total: 1235 })
        );
    }

    #[test]
    fn fresh_200_without_content_length_depends_on_flavor() {
        let h = head(200, None, None);
        assert_eq!(
            fresh(&h, CachedFlavor::Permanent, None, NO_CAP),
            DownloadPlan::Reject(RejectReason::NoContentLength)
        );
        assert_eq!(
            fresh(&h, CachedFlavor::Volatile, None, NO_CAP),
            DownloadPlan::Download {
                total: ContentLength::Unknown(VOLATILE_UNKNOWN_CONTENT_LENGTH_UPPER),
                body: ContentLength::Unknown(VOLATILE_UNKNOWN_CONTENT_LENGTH_UPPER),
                resume_offset: 0,
            }
        );
    }

    #[test]
    fn fresh_200_with_zero_content_length_rejects_for_both_flavors() {
        let h = head(200, Some(0), None);
        assert_eq!(
            fresh(&h, CachedFlavor::Permanent, None, NO_CAP),
            DownloadPlan::Reject(RejectReason::ZeroContentLength)
        );
        assert_eq!(
            fresh(&h, CachedFlavor::Volatile, Some(Cached), NO_CAP),
            DownloadPlan::Reject(RejectReason::ZeroContentLength)
        );
    }

    #[test]
    fn fresh_304_serves_cached_copy_only_when_revalidating() {
        let h = head(304, None, None);
        assert_eq!(
            fresh(&h, CachedFlavor::Volatile, Some(Cached), NO_CAP),
            DownloadPlan::NotModified(Cached)
        );
        // A 304 nobody asked for (no conditional headers were sent) is
        // relayed like any other non-200.
        assert_eq!(
            fresh(&h, CachedFlavor::Volatile, None, NO_CAP),
            DownloadPlan::Passthrough
        );
        assert_eq!(
            fresh(&h, CachedFlavor::Permanent, None, NO_CAP),
            DownloadPlan::Passthrough
        );
    }

    #[test]
    fn fresh_non_200_is_passthrough_regardless_of_headers() {
        for status in [301, 302, 307, 308, 400, 403, 404, 416, 500, 502, 503] {
            let h = head(status, Some(42), Some("bytes 0-41/42"));
            assert_eq!(
                fresh(&h, CachedFlavor::Permanent, None, NO_CAP),
                DownloadPlan::Passthrough,
                "status {status}"
            );
            assert_eq!(
                fresh(&h, CachedFlavor::Volatile, Some(Cached), NO_CAP),
                DownloadPlan::Passthrough,
                "status {status}"
            );
        }
    }

    #[test]
    fn fresh_206_is_unsolicited_even_with_valid_content_range() {
        let h = head(206, Some(10), Some("bytes 0-9/10"));
        assert_eq!(
            fresh(&h, CachedFlavor::Permanent, None, NO_CAP),
            DownloadPlan::Reject(RejectReason::Unsolicited206)
        );
        // Precedence: the poisoning guard beats the volatile revalidation
        // bookkeeping and the missing-Content-Length branch.
        assert_eq!(
            fresh(
                &head(206, None, None),
                CachedFlavor::Volatile,
                Some(Cached),
                NO_CAP
            ),
            DownloadPlan::Reject(RejectReason::Unsolicited206)
        );
    }

    #[test]
    fn resume_200_means_range_ignored() {
        let h = head(200, Some(100), None);
        assert_eq!(
            resumed(&h, 40, Some(100), NO_CAP),
            Err(ResumeAnomaly::RangeIgnored)
        );
        assert!(!ResumeAnomaly::RangeIgnored.needs_refetch());
        // The same head re-planned fresh is a normal download.
        assert_eq!(
            plan_fresh_download::<Cached>(&h, CachedFlavor::Permanent, None, NO_CAP),
            exact_download(100, 100, 0)
        );
    }

    #[test]
    fn resume_416_needs_refetch() {
        assert_eq!(
            resumed(&head(416, None, Some("bytes */100")), 40, Some(100), NO_CAP),
            Err(ResumeAnomaly::RangeNotSatisfiable)
        );
        assert!(ResumeAnomaly::RangeNotSatisfiable.needs_refetch());
    }

    #[test]
    fn resume_206_matching_remainder_downloads() {
        let h = head(206, Some(60), Some("bytes 40-99/100"));
        assert_eq!(
            resumed(&h, 40, Some(100), NO_CAP),
            Ok(exact_download(100, 60, 40))
        );
        // Unknown expected total (xattr missing) accepts any consistent total.
        assert_eq!(
            resumed(&h, 40, None, NO_CAP),
            Ok(exact_download(100, 60, 40))
        );
        // Content-Length is optional on a 206.
        assert_eq!(
            resumed(
                &head(206, None, Some("bytes 40-99/100")),
                40,
                Some(100),
                NO_CAP
            ),
            Ok(exact_download(100, 60, 40))
        );
        // Resuming the very last byte.
        assert_eq!(
            resumed(
                &head(206, Some(1), Some("bytes 99-99/100")),
                99,
                Some(100),
                NO_CAP
            ),
            Ok(exact_download(100, 1, 99))
        );
    }

    #[test]
    fn resume_206_content_range_mismatch_needs_refetch() {
        let cases = [
            None,                     // absent
            Some("garbage"),          // malformed
            Some("bytes 41-99/100"),  // does not start at the offset
            Some("bytes 40-98/100"),  // does not run to the end
            Some("bytes 40-199/200"), // total changed upstream
            Some("bytes 0-99/100"),   // whole file relabelled as partial
        ];
        for content_range in cases {
            assert_eq!(
                resumed(&head(206, None, content_range), 40, Some(100), NO_CAP),
                Err(ResumeAnomaly::ContentRangeMismatch),
                "content_range {content_range:?}"
            );
        }
        assert!(ResumeAnomaly::ContentRangeMismatch.needs_refetch());
    }

    #[test]
    fn resume_206_content_length_disagreeing_with_span_rejects() {
        assert_eq!(
            resumed(
                &head(206, Some(59), Some("bytes 40-99/100")),
                40,
                Some(100),
                NO_CAP
            ),
            Ok(DownloadPlan::Reject(
                RejectReason::InconsistentContentRange {
                    content_length: 59,
                    span: 60,
                }
            ))
        );
    }

    #[test]
    fn resume_206_oversize_total_rejects_after_consistency_check() {
        let cap = Some(nonzero!(99));
        assert_eq!(
            resumed(
                &head(206, Some(60), Some("bytes 40-99/100")),
                40,
                Some(100),
                cap
            ),
            Ok(DownloadPlan::Reject(RejectReason::Oversize { total: 100 }))
        );
        // Inconsistent framing is reported before the size cap.
        assert_eq!(
            resumed(
                &head(206, Some(1), Some("bytes 40-99/100")),
                40,
                Some(100),
                cap
            ),
            Ok(DownloadPlan::Reject(
                RejectReason::InconsistentContentRange {
                    content_length: 1,
                    span: 60,
                }
            ))
        );
    }

    #[test]
    fn resume_other_status_is_passthrough_keeping_the_partial() {
        for status in [301, 404, 500, 503] {
            assert_eq!(
                resumed(&head(status, Some(5), None), 40, Some(100), NO_CAP),
                Ok(DownloadPlan::Passthrough),
                "status {status}"
            );
        }
    }

    #[test]
    fn reject_bodies_are_stable() {
        assert_eq!(RejectReason::Unsolicited206.body(), "Unsolicited 206");
        assert_eq!(
            RejectReason::InconsistentContentRange {
                content_length: 1,
                span: 2
            }
            .body(),
            "Inconsistent Content-Range"
        );
        assert_eq!(
            RejectReason::Oversize { total: 1 }.body(),
            "Upstream resource too large"
        );
        assert_eq!(RejectReason::NoContentLength.body(), "no Content-Length");
        assert_eq!(
            RejectReason::ZeroContentLength.body(),
            "Zero Content-Length"
        );
    }

    #[cfg(feature = "hyper")]
    #[test]
    fn from_response_projects_status_and_framing() {
        let response = http::Response::builder()
            .status(206)
            .header("content-length", " 60 ")
            .header("content-range", "bytes 40-99/100")
            .body(())
            .unwrap();
        assert_eq!(
            UpstreamHead::from_response(&response),
            head(206, Some(60), Some("bytes 40-99/100"))
        );

        let response = http::Response::builder()
            .status(200)
            .header("content-length", "junk")
            .header("content-range", "bytes x-y/z")
            .body(())
            .unwrap();
        assert_eq!(
            UpstreamHead::from_response(&response),
            head(200, None, None)
        );
    }

    #[cfg(feature = "hyper")]
    #[test]
    fn from_response_chunked_overrides_content_length() {
        let response = http::Response::builder()
            .status(200)
            .header("transfer-encoding", "gzip, Chunked")
            .header("content-length", "60")
            .body(())
            .unwrap();
        assert_eq!(
            UpstreamHead::from_response(&response),
            head(200, None, None)
        );
    }
}
