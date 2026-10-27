//! Cleanup's index fetch for hyper-less builds (gated on the `mod` line with
//! `cfg(not(feature = "hyper"))`): [`cleanup_index_fetch`] answers one format
//! attempt of cleanup's fetch cascade (`cleanup/fetch.rs`) with the complete
//! index bytes, read from a fresh enough cached copy or fetched uncached through
//! `acquire::standard_upstream_connect`, or with the status or failure that
//! ended the attempt.

use std::{io::ErrorKind, num::NonZero, path::Path, time::SystemTime};

use http::{StatusCode, Uri, uri::PathAndQuery};
use tokio::io::AsyncReadExt as _;
use tracing::{debug, error};

use crate::cache_conditional::volatile_freshness;
use crate::cache_layout::ConnectionDetails;
use crate::cleanup::{FetchFailure, IndexAnswer};
use crate::deb_mirror::Mirror;
use crate::error::{ErrorReport, UpstreamFetchError};
use crate::fs_open::{
    CacheAccessFailure, count_cache_failure, hint_sequential_read, regular_file_metadata,
    tokio_nofollow_options,
};
use crate::humanfmt::HumanFmt;
use crate::integrity::note_cached_index_touch;
use crate::limits::VOLATILE_CACHE_MAX_AGE;
use crate::log_once::Logged;
use crate::metrics;
use crate::transfer_error::UpstreamError;
use crate::warn_once_or_info;

use super::acquire::{UpstreamExchange, standard_upstream_connect};

/// A cache anomaly, answered like the hyper backend's `serve_volatile_file`
/// answers it: a 500, which ends cleanup's format cascade.
const CACHE_FAILURE: IndexAnswer<Vec<u8>> = IndexAnswer::Status(StatusCode::INTERNAL_SERVER_ERROR);

/// Read cleanup's index from the already-open cache file, if fresh.
///
/// Returns `None` when the cached copy is stale (or has a future mtime) or
/// exceeds `max_bytes`, and the caller should fetch upstream; `Some` carries
/// either the cached bytes or a 500 on cache anomalies.
async fn read_cached_index(
    mut file: tokio::fs::File,
    cache_path: &Path,
    max_bytes: NonZero<u64>,
    now: SystemTime,
) -> Option<IndexAnswer<Vec<u8>>> {
    let mdata = match regular_file_metadata(&file, cache_path) {
        Ok(data) => data,
        Err(CacheAccessFailure(_)) => return Some(CACHE_FAILURE),
    };

    let modified = mdata
        .modified()
        .expect("Platform should support modification timestamps via setup check");
    let Ok(elapsed) = volatile_freshness(cache_path, modified, now) else {
        return None;
    };

    if mdata.len() > max_bytes.get() {
        warn_once_or_info!(
            "splice cleanup: cached file `{}` exceeds the {max_bytes} byte buffering cap; refetching from upstream",
            cache_path.display()
        );
        return None;
    }
    let size = usize::try_from(mdata.len()).expect("size below buffering cap fits usize");

    hint_sequential_read(&file, mdata.len(), cache_path);
    // A file growing past this stat is read whole; cleanup's reduce checks the
    // caps against the bytes actually read.
    let mut body = Vec::with_capacity(size);
    match file.read_to_end(&mut body).await {
        Ok(_bytes) => {
            debug!(
                "splice cleanup: serving `{}` from cache (age {} within {})",
                cache_path.display(),
                HumanFmt::Time(elapsed),
                HumanFmt::Time(VOLATILE_CACHE_MAX_AGE)
            );
            Some(IndexAnswer::Complete(body))
        }
        Err(err) => {
            metrics::CACHE_IO_FAILURE.increment();
            error!(
                "splice cleanup: failed to read cached file `{}`; returning 500:  {}",
                cache_path.display(),
                ErrorReport(&err)
            );
            Some(CACHE_FAILURE)
        }
    }
}

/// One format attempt of cleanup's index fetch in hyper-less builds, for the
/// index at `uri`, buffering at most `max_bytes` (`limits::packages_file_cap`
/// of its compression).
///
/// Only copies younger than `VOLATILE_CACHE_MAX_AGE` (30s) may supply
/// references. Older named indexes can omit packages introduced since their
/// fetch, even while clients keep current by-hash indexes cached. Fetch them
/// upstream; request headers cannot extend freshness. This bridge performs a
/// full, uncached fetch, while Hyper may conditionally revalidate and caches
/// what it fetched.
pub(crate) async fn cleanup_index_fetch(
    conn_details: &ConnectionDetails,
    uri: &Uri,
    max_bytes: NonZero<u64>,
) -> Result<IndexAnswer<Vec<u8>>, FetchFailure> {
    let cache_path = conn_details.cache_file_path();
    match tokio_nofollow_options().read(true).open(&cache_path).await {
        Ok(file) => {
            if let Some(answer) =
                read_cached_index(file, &cache_path, max_bytes, SystemTime::now()).await
            {
                note_cached_index_touch(conn_details, uri.path(), &cache_path);
                return Ok(answer);
            }
        }
        Err(err) if err.kind() == ErrorKind::NotFound => {}
        Err(err) => {
            count_cache_failure(&err);
            error!(
                "splice cleanup: failed to open cached file `{}`; returning 500:  {}",
                cache_path.display(),
                ErrorReport(&err)
            );
            return Ok(CACHE_FAILURE);
        }
    }
    cleanup_upstream_fetch(&conn_details.mirror, uri, max_bytes).await
}

/// The failure of an upstream fetch no download runner owns: concluded by the
/// caller, its report becomes the cause cleanup's decision log names.
fn upstream_failure(reported: &UpstreamError) -> FetchFailure {
    FetchFailure {
        status: StatusCode::BAD_GATEWAY,
        upstream: Some(UpstreamFetchError {
            reason: ErrorReport(reported).to_string(),
        }),
    }
}

async fn cleanup_upstream_fetch(
    mirror: &Mirror,
    upstream_uri: &Uri,
    max_bytes: NonZero<u64>,
) -> Result<IndexAnswer<Vec<u8>>, FetchFailure> {
    let upstream_path = upstream_uri
        .path_and_query()
        .map_or_else(|| upstream_uri.path(), PathAndQuery::as_str);
    let host_authority = mirror.format_authority();
    let exchange = match standard_upstream_connect(
        mirror.into(),
        host_authority,
        upstream_path,
        0,
        None,
        None,
        None,
    )
    .await
    {
        Ok(v) => v,
        Err(err) => {
            // Cleanup fetches run without a download runner: conclude the
            // upstream failure here; cleanup's decision log reports the
            // cause.
            let reported = err.conclude(Some(mirror), |_err| {
                Logged::debug(format_args!(
                    "splice cleanup request to {upstream_path} failed to connect/read headers"
                ))
            });
            return Err(upstream_failure(reported.get()));
        }
    };

    let status = exchange.response.status_code;

    if status != StatusCode::OK {
        // Drain the (small) error body so the connection returns to the pool;
        // the `.xz` -> `.gz` -> raw probe cascade reuses it for the next
        // format.
        exchange.dispose("splice cleanup:").await;
        return Ok(IndexAnswer::Status(status));
    }

    let max_bytes: usize = max_bytes
        .get()
        .try_into()
        .expect("constant fits into usize");
    let UpstreamExchange {
        conn: upstream,
        response: resp,
        header_buf: hdr_buf,
        header_end: hdr_end,
        reused: _,
        // Cleanup's own fetches record no time to first byte (`mirror_perf`).
        attempt_started: _,
    } = exchange;
    let body = resp
        .framing
        .read_to_vec(upstream, &hdr_buf[hdr_end..], max_bytes)
        .await
        // An empty index is the upstream fault `RejectReason::ZeroContentLength`
        // documents (its doc holds the rationale), whatever the framing: fail
        // the fetch like the hyper backend's cleanup fetches do, so cleanup
        // skips the mirror instead of reconciling against an empty reference
        // set.
        .and_then(|body| {
            if body.is_empty() {
                Err(UpstreamError::protocol("empty body"))
            } else {
                Ok(body)
            }
        });

    match body {
        Ok(body) => Ok(IndexAnswer::Complete(body)),
        Err(err) => {
            // No download runner owns this fetch either, so the body failure
            // is concluded here as well (a rate abort is the common one).
            let reported = err.conclude(Some(mirror), |err| {
                Logged::debug(format_args!(
                    "splice cleanup request to {host_authority}{upstream_path} failed to read the body:  {}",
                    ErrorReport(err)
                ))
            });
            Err(upstream_failure(reported.get()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn freshness_uses_thirty_seconds_regardless_of_the_request() {
        use std::time::Duration;
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("Packages");
        std::fs::write(&path, b"index").expect("index");
        let modified = std::fs::metadata(&path)
            .expect("metadata")
            .modified()
            .expect("mtime");
        let cap = crate::limits::MAX_DECOMPRESSED_PACKAGES_SIZE;
        for (age, fresh) in [
            (Duration::ZERO, true),
            (Duration::from_secs(29), true),
            (Duration::from_secs(30), false),
            (Duration::from_hours(6 * 24), false),
        ] {
            let file = tokio::fs::File::open(&path).await.expect("open");
            assert_eq!(
                read_cached_index(file, &path, cap, modified + age)
                    .await
                    .is_some(),
                fresh
            );
        }
        let file = tokio::fs::File::open(&path).await.expect("open");
        assert!(
            read_cached_index(file, &path, cap, modified - Duration::from_secs(1))
                .await
                .is_none(),
            "future mtimes are stale"
        );
    }

    /// A fresh copy past the buffering cap is refetched rather than read.
    #[tokio::test]
    async fn an_oversized_fresh_copy_is_refetched() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("Packages.xz");
        std::fs::write(&path, b"12345").expect("index");
        let modified = std::fs::metadata(&path)
            .expect("metadata")
            .modified()
            .expect("mtime");
        let file = tokio::fs::File::open(&path).await.expect("open");
        assert!(
            read_cached_index(file, &path, crate::nonzero!(4), modified)
                .await
                .is_none()
        );
        let file = tokio::fs::File::open(&path).await.expect("open");
        assert!(matches!(
            read_cached_index(file, &path, crate::nonzero!(5), modified).await,
            Some(IndexAnswer::Complete(body)) if body == b"12345"
        ));
    }
}
