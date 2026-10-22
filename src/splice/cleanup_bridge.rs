//! Cleanup's index fetch for hyper-less builds (gated on the `mod` line with
//! `cfg(not(feature = "hyper"))`): [`splice_cleanup_request`] serves a fresh
//! enough cached copy or fetches through `acquire::standard_upstream_connect`
//! and returns an `http::Response<ProxyCacheBody>` the way the hyper backend's
//! `process_cache_request` would; [`process_cache_request`] is the
//! signature-compatible entry cleanup calls in both builds.

use std::{io::ErrorKind, path::Path, time::SystemTime};

use http::{StatusCode, Uri, uri::PathAndQuery};
use tokio::io::AsyncReadExt as _;
use tracing::{debug, error};

use crate::cache_layout::ConnectionDetails;
use crate::deb_mirror::Mirror;
use crate::error::ErrorReport;
use crate::fs_open::{
    CacheAccessFailure, count_cache_failure, hint_sequential_read, regular_file_metadata,
    tokio_nofollow_options,
};
use crate::humanfmt::HumanFmt;
use crate::integrity::note_cached_index_touch;
use crate::limits::{self, PackagesCompression};
use crate::log_once::Logged;
use crate::metrics;
use crate::transfer_error::UpstreamError;
use crate::warn_once_or_info;
use crate::{
    AppState,
    error::UpstreamFetchError,
    limits::VOLATILE_CACHE_MAX_AGE,
    proxy_body::{ProxyCacheBody, full_body},
};

use super::acquire::{UpstreamExchange, standard_upstream_connect};

/// Empty-bodied response for the cleanup bridge (`packages.rs` only reads the
/// status on non-200s).
fn cleanup_response(status: StatusCode) -> http::Response<ProxyCacheBody> {
    http::Response::builder()
        .status(status)
        .body(full_body(bytes::Bytes::new()))
        .expect("static response is valid")
}

/// Most bytes of the index at `path` the bridge buffers:
/// `limits::packages_file_cap` for its compression (what cleanup's reduce
/// would decode at most), the decompressed ceiling for a leaf that names none.
fn buffering_cap(path: &str) -> u64 {
    let path = path.split_once('?').map_or(path, |(path, _query)| path);
    path.rsplit('/')
        .next()
        .and_then(PackagesCompression::from_filename)
        .map_or(
            limits::MAX_DECOMPRESSED_PACKAGES_SIZE,
            limits::packages_file_cap,
        )
        .get()
}

/// Serve a cleanup index request from the already-open cache file, if fresh.
///
/// Returns `None` when the cached copy is stale (or has a future mtime) and
/// the caller should fetch upstream; `Some` carries either the cached bytes
/// or a 500 on cache anomalies (mirroring the hyper backend's
/// `serve_volatile_file` error handling).
async fn serve_cached_cleanup_file(
    mut file: tokio::fs::File,
    cache_path: &Path,
    req: &http::Request<http_body_util::Empty<()>>,
    now: SystemTime,
) -> Option<http::Response<ProxyCacheBody>> {
    let mdata = match regular_file_metadata(&file, cache_path) {
        Ok(data) => data,
        Err(CacheAccessFailure(_)) => {
            return Some(cleanup_response(StatusCode::INTERNAL_SERVER_ERROR));
        }
    };

    let modified = mdata
        .modified()
        .expect("Platform should support modification timestamps via setup check");
    let Ok(elapsed) = now.duration_since(modified) else {
        warn_once_or_info!(
            "Volatile file `{}` was modified in the future; treating it as stale and refetching from upstream",
            cache_path.display()
        );
        return None;
    };
    let max_age = VOLATILE_CACHE_MAX_AGE;
    if elapsed >= max_age {
        return None;
    }

    let max_bytes = buffering_cap(req.uri().path());
    if mdata.len() > max_bytes {
        warn_once_or_info!(
            "splice cleanup: cached file `{}` exceeds the {max_bytes} byte buffering cap; refetching from upstream",
            cache_path.display()
        );
        return None;
    }
    let size = usize::try_from(mdata.len()).expect("size below buffering cap fits usize");

    hint_sequential_read(&file, mdata.len(), cache_path);
    let mut body = Vec::with_capacity(size);
    match file.read_to_end(&mut body).await {
        Ok(_bytes) => {
            debug!(
                "splice cleanup: serving `{}` from cache (age {} within {})",
                cache_path.display(),
                HumanFmt::Time(elapsed),
                HumanFmt::Time(max_age)
            );
            Some(
                http::Response::builder()
                    .status(StatusCode::OK)
                    .body(full_body(body))
                    .expect("cached response is valid"),
            )
        }
        Err(err) => {
            metrics::CACHE_IO_FAILURE.increment();
            error!(
                "splice cleanup: failed to read cached file `{}`; returning 500:  {}",
                cache_path.display(),
                ErrorReport(&err)
            );
            Some(cleanup_response(StatusCode::INTERNAL_SERVER_ERROR))
        }
    }
}

/// Cleanup index fetch for hyper-less builds: the `process_cache_request`
/// bridge in `main.rs` lands here.
///
/// Only copies younger than `VOLATILE_CACHE_MAX_AGE` (30s) may supply
/// references. Older named indexes can omit packages introduced since their
/// fetch, even while clients keep current by-hash indexes cached. Fetch them
/// upstream; request headers cannot extend freshness. This bridge performs a
/// full fetch, while Hyper may conditionally revalidate.
#[must_use]
async fn splice_cleanup_request(
    conn_details: &ConnectionDetails,
    req: &http::Request<http_body_util::Empty<()>>,
) -> http::Response<ProxyCacheBody> {
    let cache_path = conn_details.cache_file_path();
    match tokio_nofollow_options().read(true).open(&cache_path).await {
        Ok(file) => {
            if let Some(resp) =
                serve_cached_cleanup_file(file, &cache_path, req, SystemTime::now()).await
            {
                note_cached_index_touch(conn_details, req.uri().path(), &cache_path);
                return resp;
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
            return cleanup_response(StatusCode::INTERNAL_SERVER_ERROR);
        }
    }
    cleanup_upstream_fetch(&conn_details.mirror, req.uri()).await
}

#[must_use]
async fn cleanup_upstream_fetch(
    mirror: &Mirror,
    upstream_uri: &Uri,
) -> http::Response<ProxyCacheBody> {
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
            // cause from the extension.
            let reported = err.conclude(Some(mirror), |_err| {
                Logged::debug(format_args!(
                    "splice cleanup request to {upstream_path} failed to connect/read headers"
                ))
            });
            let mut resp = cleanup_response(StatusCode::BAD_GATEWAY);
            resp.extensions_mut().insert(UpstreamFetchError {
                reason: ErrorReport(reported.get()).to_string(),
            });
            return resp;
        }
    };

    let status = exchange.response.status_code;

    if status != StatusCode::OK {
        // Drain the (small) error body so the connection returns to the pool;
        // the `.xz` -> `.gz` -> raw probe cascade reuses it for the next
        // format.
        exchange.dispose("splice cleanup:").await;
        return cleanup_response(status);
    }

    let max_bytes: usize = buffering_cap(upstream_path)
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
        Ok(body) => http::Response::builder()
            .status(StatusCode::OK)
            .body(full_body(body))
            .expect("upstream response is valid"),
        Err(err) => {
            // No download runner owns this fetch either, so the body failure
            // is concluded here as well (a rate abort is the common one).
            let reported = err.conclude(Some(mirror), |err| {
                Logged::debug(format_args!(
                    "splice cleanup request to {host_authority}{upstream_path} failed to read the body:  {}",
                    ErrorReport(err)
                ))
            });
            let mut resp = cleanup_response(StatusCode::BAD_GATEWAY);
            resp.extensions_mut().insert(UpstreamFetchError {
                reason: ErrorReport(reported.get()).to_string(),
            });
            resp
        }
    }
}

#[must_use]
pub(crate) async fn process_cache_request(
    conn_details: ConnectionDetails,
    req: http::Request<http_body_util::Empty<()>>,
    _appstate: AppState,
) -> http::Response<ProxyCacheBody> {
    splice_cleanup_request(&conn_details, &req).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn freshness_uses_thirty_seconds_even_with_a_week_long_request_allowance() {
        use std::time::Duration;
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("Packages");
        std::fs::write(&path, b"index").expect("index");
        let modified = std::fs::metadata(&path)
            .expect("metadata")
            .modified()
            .expect("mtime");
        let request = http::Request::builder()
            .uri("http://mirror/debian/dists/sid/main/binary-amd64/Packages")
            .header(http::header::CACHE_CONTROL, "max-age=604800")
            .body(http_body_util::Empty::new())
            .expect("request");
        for (age, fresh) in [
            (Duration::ZERO, true),
            (Duration::from_secs(29), true),
            (Duration::from_secs(30), false),
            (Duration::from_hours(6 * 24), false),
        ] {
            let file = tokio::fs::File::open(&path).await.expect("open");
            assert_eq!(
                serve_cached_cleanup_file(file, &path, &request, modified + age)
                    .await
                    .is_some(),
                fresh
            );
        }
        let file = tokio::fs::File::open(&path).await.expect("open");
        assert!(
            serve_cached_cleanup_file(file, &path, &request, modified - Duration::from_secs(1))
                .await
                .is_none(),
            "future mtimes are stale"
        );
    }

    #[test]
    fn buffering_cap_follows_the_index_compression() {
        let compressed = limits::MAX_COMPRESSED_PACKAGES_SIZE.get();
        let raw = limits::MAX_DECOMPRESSED_PACKAGES_SIZE.get();
        assert_eq!(
            buffering_cap("/debian/dists/sid/main/binary-amd64/Packages.xz"),
            compressed
        );
        assert_eq!(
            buffering_cap("/debian/dists/sid/main/binary-amd64/Packages.gz"),
            compressed
        );
        assert_eq!(buffering_cap("/repo/Packages.gz?x=1"), compressed);
        assert_eq!(
            buffering_cap("/debian/dists/sid/main/binary-amd64/Packages"),
            raw
        );
        assert_eq!(buffering_cap("/repo/Packages.zst"), raw);
    }
}
