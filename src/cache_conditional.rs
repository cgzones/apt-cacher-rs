//! Conditional-request handling shared across delivery paths.
//!
//! Centralizes the cached representation's metadata view (`ETag` /
//! `Last-Modified` / cache `Age`) and the RFC 9110 §13.1 precedence rules for
//! evaluating `If-None-Match` / `If-Modified-Since` against a cached file.
//! Both the hyper path in `main.rs` and the sendfile path in
//! `sendfile_conn.rs` previously rebuilt this view inline; sharing it keeps
//! their behavior in lockstep.

#[cfg(feature = "sendfile")]
use std::path::Path;

use crate::cache_metadata::UpstreamMetadata;
#[cfg(feature = "sendfile")]
use crate::cache_metadata::{self, CacheMetadataKeyRef};
use crate::http_etag::if_none_match;
use crate::http_range::{HttpDate, cache_file_http_date, compute_age};

/// Pre-computed cache representation metadata used to evaluate conditional
/// request headers and to populate response headers (`Last-Modified`, `ETag`,
/// `Age`).
pub(crate) struct CacheInfo {
    pub(crate) file_etag: Option<String>,
    pub(crate) last_modified_for_ims: HttpDate,
    pub(crate) last_modified_str: String,
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
        key: &CacheMetadataKeyRef<'_>,
    ) -> Self {
        let resolved = cache_metadata::store().resolve(key, file, file_path);
        Self::with_meta(metadata, &resolved)
    }

    /// Build a [`CacheInfo`] from a caller-supplied [`UpstreamMetadata`]
    /// snapshot — typically the one carried on
    /// [`crate::ActiveDownloadStatus::Download`] for late-joiner reads, so
    /// no xattr/cache lookup happens at all.
    #[must_use]
    pub(crate) fn with_meta(metadata: &std::fs::Metadata, meta: &UpstreamMetadata) -> Self {
        let cache_ts = cache_file_http_date(metadata);

        let (last_modified_for_ims, last_modified_str) = match meta.last_modified.as_ref() {
            Some((s, time)) => (*time, s.clone()),
            None => (cache_ts, cache_ts.format()),
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
}
