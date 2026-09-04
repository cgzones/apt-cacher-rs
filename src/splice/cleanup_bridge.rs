//! Cleanup's index fetch for hyper-less builds (gated on the `mod` line with
//! `cfg(not(feature = "hyper"))`): [`splice_cleanup_request`] serves a fresh
//! enough cached copy or fetches through `acquire::standard_upstream_connect`
//! and returns an `http::Response<ProxyCacheBody>` the way the hyper backend's
//! `process_cache_request` would; [`process_cache_request`] is the
//! signature-compatible entry cleanup calls in both builds.

use std::{io::ErrorKind, path::Path, time::Duration};

use http::StatusCode;
use tokio::io::AsyncReadExt as _;
use tracing::{debug, error};

use crate::cache_layout::ConnectionDetails;
use crate::deb_mirror::Mirror;
use crate::error::ErrorReport;
use crate::fs_open::{
    CacheAccessFailure, hint_sequential_read, regular_file_metadata, tokio_nofollow_options,
};
use crate::humanfmt::HumanFmt;
use crate::limits;
use crate::metrics;
use crate::warn_once_or_info;
use crate::{
    AppState,
    error::UpstreamFetchError,
    limits::VOLATILE_CACHE_MAX_AGE,
    proxy_body::{ProxyCacheBody, full_body},
};

use super::UpstreamFailure;
use super::acquire::{UpstreamExchange, standard_upstream_connect};

/// Empty-bodied response for the cleanup bridge (`packages.rs` only reads the
/// status on non-200s).
fn cleanup_response(status: StatusCode) -> http::Response<ProxyCacheBody> {
    http::Response::builder()
        .status(status)
        .body(full_body(bytes::Bytes::new()))
        .expect("static response is valid")
}

/// Parse the `max-age` directive from a request's `Cache-Control` header.
fn cache_control_max_age(req: &http::Request<http_body_util::Empty<()>>) -> Option<Duration> {
    let value = req
        .headers()
        .get(http::header::CACHE_CONTROL)?
        .to_str()
        .ok()?;
    value
        .split(',')
        .find_map(|directive| directive.trim().strip_prefix("max-age="))
        .and_then(|secs| secs.parse::<u64>().ok())
        .map(Duration::from_secs)
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
    let Ok(elapsed) = modified.elapsed() else {
        warn_once_or_info!(
            "Volatile file `{}` was modified in the future; treating it as stale and refetching from upstream",
            cache_path.display()
        );
        return None;
    };
    let max_age = cache_control_max_age(req).unwrap_or(VOLATILE_CACHE_MAX_AGE);
    if elapsed >= max_age {
        return None;
    }

    let max_bytes = limits::MAX_DECOMPRESSED_PACKAGES_SIZE.get();
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
/// A cached copy younger than the request's `Cache-Control: max-age`
/// (cleanup sends 1 week) is served without touching upstream. This
/// deliberately diverges from the hyper backend, which revalidates
/// conditionally past `VOLATILE_CACHE_MAX_AGE` (30s): without conditional
/// refetch machinery here yet, honoring the caller-declared max-age avoids a
/// full re-download of every index each cleanup cycle, and a stale index errs
/// toward *keeping* cached debs — the conservative direction for cleanup.
#[must_use]
async fn splice_cleanup_request(
    conn_details: &ConnectionDetails,
    req: &http::Request<http_body_util::Empty<()>>,
) -> http::Response<ProxyCacheBody> {
    let cache_path = conn_details.cache_file_path();
    match tokio_nofollow_options().read(true).open(&cache_path).await {
        Ok(file) => {
            if let Some(resp) = serve_cached_cleanup_file(file, &cache_path, req).await {
                return resp;
            }
        }
        Err(err) if err.kind() == ErrorKind::NotFound => {}
        Err(err) => {
            metrics::CACHE_IO_FAILURE.increment();
            error!(
                "splice cleanup: failed to open cached file `{}`; returning 500:  {}",
                cache_path.display(),
                ErrorReport(&err)
            );
            return cleanup_response(StatusCode::INTERNAL_SERVER_ERROR);
        }
    }
    cleanup_upstream_fetch(&conn_details.mirror, &req.uri().to_string()).await
}

#[must_use]
async fn cleanup_upstream_fetch(
    mirror: &Mirror,
    upstream_uri: &str,
) -> http::Response<ProxyCacheBody> {
    let upstream_path_buf = upstream_uri
        .parse::<http::Uri>()
        .ok()
        .and_then(|uri| uri.path_and_query().map(|pq| pq.as_str().to_owned()));
    let upstream_path = upstream_path_buf.as_deref().unwrap_or(upstream_uri);
    let host_authority = mirror.format_authority();
    let UpstreamExchange {
        conn: mut upstream,
        response: resp,
        header_buf: hdr_buf,
        header_end: hdr_end,
        reused: _,
    } = match standard_upstream_connect(mirror, &host_authority, upstream_path, 0, None, None, None)
        .await
    {
        Ok(v) => v,
        Err(UpstreamFailure {
            err,
            logged: _logged,
        }) => {
            debug!("splice cleanup request to {upstream_path} failed to connect/read headers");
            let mut resp = cleanup_response(StatusCode::BAD_GATEWAY);
            // The throw site already logged the failure with its context;
            // hand cleanup's decision log the transport cause the same way
            // the hyper backend does, rather than a bare 502.
            resp.extensions_mut().insert(UpstreamFetchError {
                reason: ErrorReport(&err).to_string(),
            });
            return resp;
        }
    };

    let status = resp.status_code;
    let body_prefix = &hdr_buf[hdr_end..];

    if status != StatusCode::OK {
        // Drain the (small) error body so the connection returns to the pool;
        // the `.xz` -> `.gz` -> raw probe cascade reuses it for the next format.
        // Oversized or unreadable error bodies mark the connection non-poolable
        // instead (via the cap error or `inspect_err`).
        const MAX_ERROR_BODY_DRAIN: usize = 64 * 1024;
        if let Err(err) = resp
            .framing
            .read_to_vec(&mut upstream, body_prefix, MAX_ERROR_BODY_DRAIN)
            .await
        {
            debug!(
                "splice cleanup request to {host_authority}{upstream_path} failed to drain the error body:  {}",
                ErrorReport(&err)
            );
        }
        return cleanup_response(status);
    }

    let max_bytes: usize = limits::MAX_DECOMPRESSED_PACKAGES_SIZE
        .get()
        .try_into()
        .expect("constant fits into usize");
    let body = resp
        .framing
        .read_to_vec(&mut upstream, body_prefix, max_bytes)
        .await;

    match body {
        Ok(body) => http::Response::builder()
            .status(StatusCode::OK)
            .body(full_body(body))
            .expect("upstream response is valid"),
        Err(err) => {
            debug!(
                "splice cleanup request to {host_authority}{upstream_path} failed to read the body:  {}",
                ErrorReport(&err)
            );
            let mut resp = cleanup_response(StatusCode::BAD_GATEWAY);
            resp.extensions_mut().insert(UpstreamFetchError {
                reason: ErrorReport(&err).to_string(),
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
