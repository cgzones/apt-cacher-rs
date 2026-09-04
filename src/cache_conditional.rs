//! Conditional-request handling shared across delivery paths.
//!
//! Centralizes the cached representation's metadata view (`ETag` /
//! `Last-Modified` / cache `Age`), the RFC 9110 §13.1 precedence rules for
//! evaluating `If-None-Match` / `If-Modified-Since` against a cached file,
//! and - via [`CacheInfo::plan`] - the whole 304 / 416 / 206 / 200 decision
//! for a fully-cached serve, including `Range` / `If-Range`.  The plan is
//! pure: it neither touches I/O nor writes a response, so the hyper path in
//! `hyper_conn.rs` and the sendfile path in `sendfile_conn.rs` share one
//! decision and only differ in how they emit it.  [`RangeRequestHeaders`]
//! carries the four request headers the plan reads, extracted once per
//! backend representation (`extract` for httparse, `from_http` for hyper),
//! so the malformed-header logging lives here too.

#[cfg(feature = "sendfile")]
use std::path::Path;
use std::sync::Arc;

#[cfg(feature = "hyper")]
use http::HeaderMap;
use http::StatusCode;

#[cfg(feature = "sendfile")]
use crate::cache_layout::CacheEntryKeyRef;
#[cfg(feature = "sendfile")]
use crate::cache_metadata;
#[cfg(feature = "sendfile")]
use crate::http_helpers::find_header;
use crate::{
    cache_metadata::UpstreamMetadata,
    client_info::ClientInfo,
    http_etag::if_none_match,
    http_range::{HttpDate, ParsedRange, cache_file_http_date, compute_age, http_parse_range},
    warn_once_or_debug,
};

/// Raw `Range` / `If-Range` / `If-None-Match` / `If-Modified-Since` values
/// from a client request, as the plan reads them.  Header values that are
/// not valid UTF-8 are treated as absent.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct RangeRequestHeaders<'a> {
    pub(crate) range: Option<&'a str>,
    pub(crate) if_range: Option<&'a str>,
    pub(crate) if_none_match: Option<&'a str>,
    pub(crate) if_modified_since: Option<&'a str>,
}

impl<'a> RangeRequestHeaders<'a> {
    /// Extract from an httparse header list (sendfile / splice backends).
    /// Silent on non-UTF-8 values, like every other `find_header` lookup.
    #[cfg(feature = "sendfile")]
    #[must_use]
    pub(crate) fn extract(headers: &[httparse::Header<'a>]) -> Self {
        use http::header::{IF_MODIFIED_SINCE, IF_NONE_MATCH, IF_RANGE, RANGE};

        Self {
            range: find_header(headers, &RANGE),
            if_range: find_header(headers, &IF_RANGE),
            if_none_match: find_header(headers, &IF_NONE_MATCH),
            if_modified_since: find_header(headers, &IF_MODIFIED_SINCE),
        }
    }

    /// Extract from a hyper header map.  A non-UTF-8 precondition header is
    /// dropped with a one-shot warning: silently ignoring one turns a
    /// conditional request into an unconditional one.  `If-Range` is only
    /// read alongside a `Range` (it is meaningless without one), and a
    /// non-UTF-8 `Range` is ignored silently - RFC 9110 §14.2 says to serve
    /// the full entity for a malformed `Range` anyway.
    #[cfg(feature = "hyper")]
    #[must_use]
    pub(crate) fn from_http(headers: &'a HeaderMap, client: &ClientInfo) -> Self {
        use http::header::{IF_MODIFIED_SINCE, IF_NONE_MATCH, IF_RANGE, RANGE, ToStrError};

        use crate::warn_once;

        let if_none_match = headers.get(IF_NONE_MATCH).and_then(|v| match v.to_str() {
            Ok(s) => Some(s),
            Err(_err @ ToStrError { .. }) => {
                warn_once!(
                    "Client {client} sent an invalid If-None-Match header {v:?}; ignoring the precondition"
                );
                None
            }
        });
        let if_modified_since = headers.get(IF_MODIFIED_SINCE).and_then(|v| match v.to_str() {
            Ok(s) => Some(s),
            Err(_err @ ToStrError { .. }) => {
                warn_once!(
                    "Client {client} sent an invalid If-Modified-Since header {v:?}; ignoring the precondition"
                );
                None
            }
        });
        let range = headers.get(RANGE).and_then(|v| v.to_str().ok());
        // A dropped If-Range is worse than a dropped Range: the parser
        // reads `None` as "no precondition sent" and answers an
        // unconditional 206, so a resuming client can staple bytes onto
        // a different revision.
        let if_range = range.and_then(|_| headers.get(IF_RANGE)).and_then(|v| match v.to_str() {
            Ok(s) => Some(s),
            Err(_err @ ToStrError { .. }) => {
                warn_once!(
                    "Client {client} sent an invalid If-Range header {v:?}; serving the range unconditionally"
                );
                None
            }
        });

        Self {
            range,
            if_range,
            if_none_match,
            if_modified_since,
        }
    }
}

/// Byte-range parameters for serving a cached representation.  A present
/// `Content-Range` *is* the 206-ness of the delivery, so the status and the
/// partial flag are derived rather than stored alongside it.
#[derive(Debug, PartialEq, Eq)]
#[expect(
    clippy::struct_field_names,
    reason = "the fields are named after the response headers they render into"
)]
pub(crate) struct ServeParams {
    pub(crate) content_start: u64,
    pub(crate) content_length: u64,
    pub(crate) content_range: Option<String>,
}

/// The client's `Range` is syntactically valid but no byte of the
/// representation satisfies it ([`ServeParams::from_parsed`]); answer 416.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct RangeNotSatisfiable;

impl ServeParams {
    /// The whole representation as a 200.
    #[must_use]
    pub(crate) const fn full(file_size: u64) -> Self {
        Self {
            content_start: 0,
            content_length: file_size,
            content_range: None,
        }
    }

    /// Resolve an already-parsed `Range` (`None` when the request carried
    /// none) against the representation's `file_size`. A malformed `Range`
    /// and a failed `If-Range` precondition both serve the whole
    /// representation (RFC 9110 sections 14.2 and 13.1.5).
    ///
    /// The cached-serve planner ([`CacheInfo::plan`]) resolves the same three
    /// outcomes inline because it also owns the malformed-`Range` warning and
    /// the 304 precedence; every other serve path goes through here, so they
    /// cannot drift.
    pub(crate) fn from_parsed(
        parsed: Option<ParsedRange>,
        file_size: u64,
    ) -> Result<Self, RangeNotSatisfiable> {
        match parsed {
            Some(ParsedRange::NotSatisfiable) => Err(RangeNotSatisfiable),
            Some(ParsedRange::Satisfiable {
                content_range,
                start,
                length,
            }) => Ok(Self {
                content_start: start,
                content_length: length,
                content_range: Some(content_range),
            }),
            Some(ParsedRange::Invalid | ParsedRange::IfRangeFailed) | None => {
                Ok(Self::full(file_size))
            }
        }
    }

    /// Whether this is a 206 delivery of a sub-range.
    #[must_use]
    pub(crate) fn is_partial(&self) -> bool {
        self.content_range.is_some()
    }

    /// One past the last representation byte to send. Only the splice
    /// backend needs it: the others hand a start and a length to the kernel.
    #[cfg(feature = "splice")]
    #[must_use]
    pub(crate) const fn content_end(&self) -> u64 {
        self.content_start + self.content_length
    }

    #[must_use]
    pub(crate) fn http_status(&self) -> StatusCode {
        if self.is_partial() {
            StatusCode::PARTIAL_CONTENT
        } else {
            StatusCode::OK
        }
    }

    /// The status line of a hand-rendered response head. Only the splice
    /// backend renders one; the others go through `ResponseHead`.
    #[cfg(feature = "splice")]
    #[must_use]
    pub(crate) fn status_line(&self) -> &'static str {
        if self.is_partial() {
            "206 Partial Content"
        } else {
            "200 OK"
        }
    }
}

/// Outcome of [`CacheInfo::plan`].  The caller emits the response: a 304 or
/// 416 without a body, or the bytes described by the [`ServeParams`].
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ServePlan {
    /// The preconditions hold; answer 304 Not Modified.
    NotModified,
    /// A syntactically valid `Range` that no byte of the file satisfies;
    /// answer 416 with `Content-Range: bytes */{file_size}`.
    NotSatisfiable,
    /// Serve the file (200) or the requested sub-range (206).
    Serve(ServeParams),
}

/// Pre-computed cache representation metadata used to evaluate conditional
/// request headers and to populate response headers (`Last-Modified`, `ETag`,
/// `Age`).
pub(crate) struct CacheInfo {
    pub(crate) file_etag: Option<Arc<str>>,
    pub(crate) last_modified_for_ims: HttpDate,
    pub(crate) last_modified_str: Arc<str>,
    pub(crate) age: u32,
}

impl CacheInfo {
    /// Build a [`CacheInfo`] for a post-flight cache-hit serve, consulting
    /// the in-process [`cache_metadata`] cache before any xattr read.
    /// On miss, the cache lazy-loads from xattrs.
    #[cfg(feature = "sendfile")]
    #[must_use]
    pub(crate) fn resolve(
        file: &tokio::fs::File,
        file_path: &Path,
        metadata: &std::fs::Metadata,
        key: &CacheEntryKeyRef<'_>,
    ) -> Self {
        let resolved = cache_metadata::store().resolve(key, file, file_path);
        Self::with_meta(metadata, &resolved)
    }

    /// Build a [`CacheInfo`] from a caller-supplied [`UpstreamMetadata`]
    /// snapshot — typically the one carried on
    /// [`crate::active_downloads::ActiveDownloadStatus::Download`] for late-joiner reads, so
    /// no xattr/cache lookup happens at all.
    #[must_use]
    pub(crate) fn with_meta(metadata: &std::fs::Metadata, meta: &UpstreamMetadata) -> Self {
        let cache_ts = cache_file_http_date(metadata);

        let (last_modified_for_ims, last_modified_str) = match meta.last_modified.as_ref() {
            Some((s, time)) => (*time, Arc::clone(s)),
            None => (cache_ts, cache_ts.format().into()),
        };

        let age = compute_age(metadata);

        Self {
            file_etag: meta.etag.clone(),
            last_modified_for_ims,
            last_modified_str,
            age,
        }
    }

    /// Apply RFC 9110 §13.1.2 precedence: `If-None-Match` evaluated against the
    /// stored `ETag` wins; otherwise fall back to `If-Modified-Since` against the
    /// stored `Last-Modified`. Header values come pre-decoded as strings;
    /// unparsable values are treated as absent.
    #[must_use]
    pub(crate) fn decide_serve_304(
        &self,
        if_none_match_header: Option<&str>,
        if_modified_since_header: Option<&str>,
    ) -> bool {
        if let Some(inm) = if_none_match_header {
            return self
                .file_etag
                .as_deref()
                .is_some_and(|etag| if_none_match(inm, etag));
        }

        if let Some(ims) = if_modified_since_header
            && let Some(ims_time) = HttpDate::parse(ims)
        {
            return self.last_modified_for_ims <= ims_time;
        }

        false
    }

    /// Decide how to answer a request for this representation of
    /// `file_size` bytes: the RFC 9110 §13.1.2 conditional precedence
    /// ([`Self::decide_serve_304`]) first, then `Range` / `If-Range` per
    /// [`http_parse_range`].  A malformed `Range` is ignored (full 200, RFC
    /// 9110 §14.2) and a failed `If-Range` serves the full entity.  Pure: the
    /// caller writes the 304 / 416 or the bytes.  `client` is named only in
    /// the malformed-Range log line.
    #[must_use]
    pub(crate) fn plan(
        &self,
        file_size: u64,
        headers: &RangeRequestHeaders<'_>,
        client: &ClientInfo,
    ) -> ServePlan {
        if self.decide_serve_304(headers.if_none_match, headers.if_modified_since) {
            return ServePlan::NotModified;
        }

        if let Some(range) = headers.range {
            let parsed = http_parse_range(
                range,
                headers.if_range,
                file_size,
                self.last_modified_for_ims,
                self.file_etag.as_deref(),
            );
            if matches!(parsed, ParsedRange::Invalid) {
                // RFC 9110 says to ignore a malformed Range and serve the
                // whole entity, which is what `from_parsed` does -- but a
                // client that expected a resume silently receives the full
                // object, so say so. (An `If-Range` that did not match is an
                // ordinary outcome and stays quiet: the client asked for the
                // full entity if the validator moved on.)
                warn_once_or_debug!(
                    "Ignoring malformed Range header `{}` from client {client}; serving the full file",
                    range.escape_debug()
                );
            }
            return match ServeParams::from_parsed(Some(parsed), file_size) {
                Ok(params) => ServePlan::Serve(params),
                Err(RangeNotSatisfiable) => ServePlan::NotSatisfiable,
            };
        }

        ServePlan::Serve(ServeParams::full(file_size))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::local_client;

    const ETAG: &str = "\"abc123\"";
    const LAST_MODIFIED: &str = "Sun, 06 Nov 1994 08:49:37 GMT";
    const SIZE: u64 = 1000;

    fn info(etag: Option<&str>) -> CacheInfo {
        CacheInfo {
            file_etag: etag.map(Arc::from),
            last_modified_for_ims: HttpDate::parse(LAST_MODIFIED).unwrap(),
            last_modified_str: Arc::from(LAST_MODIFIED),
            age: 7,
        }
    }

    fn full() -> ServePlan {
        ServePlan::Serve(ServeParams {
            content_start: 0,
            content_length: SIZE,
            content_range: None,
        })
    }

    #[test]
    fn plan_without_headers_serves_full_file() {
        let plan = info(Some(ETAG)).plan(SIZE, &RangeRequestHeaders::default(), &local_client());
        assert_eq!(plan, full());
        let ServePlan::Serve(params) = plan else {
            unreachable!("asserted above")
        };
        assert!(!params.is_partial());
    }

    #[test]
    fn plan_if_none_match_wins_over_range() {
        let headers = RangeRequestHeaders {
            range: Some("bytes=0-99"),
            if_none_match: Some(ETAG),
            ..RangeRequestHeaders::default()
        };
        assert_eq!(
            info(Some(ETAG)).plan(SIZE, &headers, &local_client()),
            ServePlan::NotModified
        );
    }

    #[test]
    fn plan_if_none_match_mismatch_ignores_if_modified_since() {
        // RFC 9110 precedence: a present If-None-Match that does not match
        // means "modified", even when If-Modified-Since alone would say 304.
        let headers = RangeRequestHeaders {
            if_none_match: Some("\"other\""),
            if_modified_since: Some(LAST_MODIFIED),
            ..RangeRequestHeaders::default()
        };
        assert_eq!(
            info(Some(ETAG)).plan(SIZE, &headers, &local_client()),
            full()
        );
    }

    #[test]
    fn plan_if_modified_since_yields_not_modified() {
        let headers = RangeRequestHeaders {
            if_modified_since: Some(LAST_MODIFIED),
            ..RangeRequestHeaders::default()
        };
        assert_eq!(
            info(None).plan(SIZE, &headers, &local_client()),
            ServePlan::NotModified
        );
    }

    #[test]
    fn plan_satisfiable_range_serves_partial() {
        let headers = RangeRequestHeaders {
            range: Some("bytes=100-199"),
            ..RangeRequestHeaders::default()
        };
        let plan = info(Some(ETAG)).plan(SIZE, &headers, &local_client());
        let ServePlan::Serve(params) = plan else {
            unreachable!("expected Serve, got {plan:?}")
        };
        assert_eq!(params.http_status(), StatusCode::PARTIAL_CONTENT);
        assert_eq!(params.content_start, 100);
        assert_eq!(params.content_length, 100);
        assert_eq!(params.content_range.as_deref(), Some("bytes 100-199/1000"));
        assert!(params.is_partial());
    }

    #[test]
    fn plan_unsatisfiable_range_yields_416() {
        let headers = RangeRequestHeaders {
            range: Some("bytes=1000-"),
            ..RangeRequestHeaders::default()
        };
        assert_eq!(
            info(None).plan(SIZE, &headers, &local_client()),
            ServePlan::NotSatisfiable
        );
    }

    #[test]
    fn plan_malformed_range_serves_full_file() {
        let headers = RangeRequestHeaders {
            range: Some("items=0-9"),
            ..RangeRequestHeaders::default()
        };
        assert_eq!(info(None).plan(SIZE, &headers, &local_client()), full());
    }

    #[test]
    fn plan_if_range_matching_etag_serves_partial() {
        let headers = RangeRequestHeaders {
            range: Some("bytes=500-"),
            if_range: Some(ETAG),
            ..RangeRequestHeaders::default()
        };
        let plan = info(Some(ETAG)).plan(SIZE, &headers, &local_client());
        assert!(
            matches!(
                &plan,
                ServePlan::Serve(ServeParams {
                    content_start: 500,
                    content_length: 500,
                    content_range: Some(_),
                })
            ),
            "expected 206, got {plan:?}"
        );
    }

    #[test]
    fn plan_if_range_mismatch_serves_full_file() {
        let headers = RangeRequestHeaders {
            range: Some("bytes=500-"),
            if_range: Some("\"stale\""),
            ..RangeRequestHeaders::default()
        };
        assert_eq!(
            info(Some(ETAG)).plan(SIZE, &headers, &local_client()),
            full()
        );
        // Without a stored ETag no strong comparison can succeed either.
        assert_eq!(info(None).plan(SIZE, &headers, &local_client()), full());
    }

    #[test]
    fn decide_serve_304_precedence_and_parse_failures() {
        let tagged = info(Some(ETAG));

        // An unparsable If-Modified-Since is treated as absent, not as a
        // passing precondition.
        assert!(!tagged.decide_serve_304(None, Some("garbage")));
        // "not modified since" is `stored <= sent`, so a client timestamp
        // newer than the stored validator still yields 304.
        assert!(tagged.decide_serve_304(None, Some("Mon, 07 Nov 1994 08:49:37 GMT")));
        // An older one does not.
        assert!(!tagged.decide_serve_304(None, Some("Sat, 05 Nov 1994 08:49:37 GMT")));
        // A present but non-matching If-None-Match ends the evaluation: the
        // date is never consulted (RFC 9110 section 13.1.3).
        assert!(!tagged.decide_serve_304(Some("\"other\""), Some(LAST_MODIFIED)));
        // The `*` wildcard matches whenever an ETag is stored -- but *only*
        // then.  RFC 9110 section 13.1.2 makes it match any stored
        // representation; a cached file without an ETag xattr therefore gets
        // a 200 where the RFC allows a 304.  Known deviation, harmless for
        // APT clients, which do not send `If-None-Match: *`.
        assert!(tagged.decide_serve_304(Some("*"), None));
        assert!(!info(None).decide_serve_304(Some("*"), None));
    }

    #[cfg(feature = "sendfile")]
    #[test]
    fn extract_reads_all_four_headers_case_insensitively() {
        let headers = [
            httparse::Header {
                name: "range",
                value: b"bytes=0-9",
            },
            httparse::Header {
                name: "If-Range",
                value: ETAG.as_bytes(),
            },
            httparse::Header {
                name: "IF-NONE-MATCH",
                value: b"*",
            },
            httparse::Header {
                name: "if-modified-since",
                value: LAST_MODIFIED.as_bytes(),
            },
        ];
        let extracted = RangeRequestHeaders::extract(&headers);
        assert_eq!(extracted.range, Some("bytes=0-9"));
        assert_eq!(extracted.if_range, Some(ETAG));
        assert_eq!(extracted.if_none_match, Some("*"));
        assert_eq!(extracted.if_modified_since, Some(LAST_MODIFIED));
    }

    /// A non-UTF-8 precondition must be dropped, not silently mistaken for a
    /// value: dropping turns the request unconditional, which is safe, while
    /// misreading it could answer a stale 304 or a mis-stitched 206.
    #[cfg(feature = "hyper")]
    #[test]
    fn from_http_drops_non_utf8_headers() {
        use http::HeaderValue;
        use http::header::{IF_MODIFIED_SINCE, IF_NONE_MATCH, IF_RANGE, RANGE};

        let invalid = HeaderValue::from_bytes(b"\xff").expect("obs-text is a valid header value");
        let mut headers = HeaderMap::new();
        headers.insert(IF_NONE_MATCH, invalid.clone());
        headers.insert(IF_MODIFIED_SINCE, invalid.clone());
        headers.insert(RANGE, HeaderValue::from_static("bytes=0-9"));
        headers.insert(IF_RANGE, invalid);

        let extracted = RangeRequestHeaders::from_http(&headers, &local_client());
        assert_eq!(extracted.range, Some("bytes=0-9"));
        assert_eq!(extracted.if_range, None);
        assert_eq!(extracted.if_none_match, None);
        assert_eq!(extracted.if_modified_since, None);
    }

    /// `If-Range` is meaningless without a `Range`, so it is never read then
    /// -- and a request carrying only `If-Range` gets the full entity.
    #[cfg(feature = "hyper")]
    #[test]
    fn from_http_ignores_if_range_without_range() {
        use http::HeaderValue;
        use http::header::IF_RANGE;

        let mut headers = HeaderMap::new();
        headers.insert(IF_RANGE, HeaderValue::from_static(ETAG));

        let extracted = RangeRequestHeaders::from_http(&headers, &local_client());
        assert_eq!(extracted.range, None);
        assert_eq!(extracted.if_range, None);
        assert_eq!(
            info(Some(ETAG)).plan(SIZE, &extracted, &local_client()),
            full()
        );
    }

    #[test]
    fn plan_if_range_date_must_match_exactly() {
        let exact = RangeRequestHeaders {
            range: Some("bytes=0-0"),
            if_range: Some(LAST_MODIFIED),
            ..RangeRequestHeaders::default()
        };
        assert!(matches!(
            info(None).plan(SIZE, &exact, &local_client()),
            ServePlan::Serve(ServeParams {
                content_range: Some(_),
                ..
            })
        ));
        let later = RangeRequestHeaders {
            if_range: Some("Sun, 06 Nov 1994 08:49:38 GMT"),
            ..exact
        };
        assert_eq!(info(None).plan(SIZE, &later, &local_client()), full());
    }
}
