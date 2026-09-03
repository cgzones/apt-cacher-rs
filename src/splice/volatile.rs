//! Buffered download path for volatile responses without `Content-Length`:
//! [`handle_volatile_buffered_download`] reads the whole body into memory (up
//! to 1 MiB), serves it to the client and caches it, bypassing splice(2).
//! Shares the response-head, cache-target, commit and completion-log helpers
//! with the drive in `mod.rs`.

use std::num::NonZero;

use http::StatusCode;
use tokio::io::AsyncWriteExt as _;
use tracing::{debug, error};

use crate::cache_conditional::RangeRequestHeaders;
use crate::cache_layout::ConnectionDetails;
use crate::error::ErrorReport;
use crate::guards::InitBarrier;
use crate::http_helpers::write_invalid_response;
use crate::http_range::{HttpDate, ParsedRange, http_parse_range};
use crate::partial_file;
use crate::precise_instant::PreciseInstant;
use crate::rate_checker::{RateCheckDirection, RateChecker};
use crate::sendfile_conn::write_all_to_stream_rated;
use crate::tcp_cork_guard::CorkGuard;
use crate::{
    client_counter, global_config, limits::VOLATILE_UNKNOWN_CONTENT_LENGTH_UPPER, metrics,
    warn_once, warn_once_or_debug, warn_once_or_info_logged,
};

use super::http::{BodyFraming, UpstreamResponse};
use super::upstream::{ConnLabel, PoolGuard};
use super::{
    AfterHeaderSide, ClientConn, CompletionClient, RateTimestamps, SpliceProxyError,
    UpstreamFailure, commit_and_record, log_splice_completion, prepare_cache_target,
    record_delivery, resolve_client_range, write_splice_response_headers,
};

/// Handle the full lifecycle for volatile files whose upstream response has no
/// Content-Length.  The entire body is buffered into memory (up to 1 MiB),
/// then served to the client and cached, bypassing splice(2).
#[expect(
    clippy::too_many_arguments,
    reason = "lifecycle function threading full context"
)]
pub(super) async fn handle_volatile_buffered_download(
    upstream: &mut PoolGuard,
    client: ClientConn<'_>,
    conn_details: &ConnectionDetails,
    // The original (pre-redirect) client request URI path. Used for
    // `RenamePlan.raw_uri_path` and the recorded `Origin` so registry keys
    // and DB origin rows match the hyper backend.
    original_uri_path: &str,
    upstream_resp: &UpstreamResponse,
    header_buf: &[u8],
    header_end: usize,
    ibarrier: InitBarrier<'_>,
    client_range: RangeRequestHeaders<'_>,
    conn_label: ConnLabel,
) -> Result<(), SpliceProxyError> {
    let max_bytes: usize = VOLATILE_UNKNOWN_CONTENT_LENGTH_UPPER
        .get()
        .try_into()
        .expect("constant fits"); // TODO: const conversion once stable
    let body_prefix = &header_buf[header_end..];

    // Capture t_req_sent before buffering so the upstream-rate window is never
    // inverted. The fallback is a pre-read now() so t_req_sent <= t_upstream_done.
    let t_req_sent = upstream_resp
        .request_sent_at
        .unwrap_or_else(PreciseInstant::now);

    // Account this buffered serve under `ACTIVE_CLIENT_DOWNLOADS` for the
    // duration of the function (RAII drop on every return path).  Mirrors
    // the canonical `splice_proxy_body{,_tls}` holders; the buffered path
    // bypasses those and would otherwise undercount.
    let _client_count = client_counter::ClientDownload::new();

    // Buffer the entire body into memory. This path is only reached without a
    // usable Content-Length (the length-delimited case is spliced), so framing
    // is chunked or close-delimited; a `ContentLength` body is still read
    // correctly (to its declared length) but flags the routing slip.
    if let BodyFraming::ContentLength(len) = upstream_resp.framing {
        warn_once!(
            "splice proxy: volatile buffered download of {} reached with a Content-Length body ({len} bytes)",
            conn_details.debname
        );
    }
    let body = upstream_resp
        .framing
        .read_to_vec(upstream, body_prefix, max_bytes)
        .await
        .map_err(|err| {
            let logged = warn_once_or_info_logged!(
                "splice proxy: volatile buffered download failed for {}; returning 502:  {}",
                conn_details.debname,
                ErrorReport(&err)
            );
            SpliceProxyError::Upstream(UpstreamFailure { err, logged })
        })?;

    let mut rates = RateTimestamps::new(t_req_sent);

    let Some(total_content_length) = NonZero::new(body.len() as u64) else {
        debug!(
            "splice proxy: zero-length volatile body for {} from mirror {}",
            conn_details.debname, conn_details.mirror
        );
        write_invalid_response(
            client.stream,
            client.version,
            client.action,
            StatusCode::BAD_GATEWAY,
            "zero-length body",
            None,
        )
        .await
        .map_err(|err| SpliceProxyError::Client {
            phase: "volatile zero-body 502",
            err,
        })?;
        return Ok(());
    };

    debug!(
        "splice proxy{conn_label}: buffered volatile download of {} from mirror {} for client {} ({} bytes)...",
        conn_details.debname, conn_details.mirror, conn_details.client, total_content_length
    );

    // Parse client Range against the now-known total size.
    let cache_time = HttpDate::now();
    let client_range_result = client_range.range.map(|range| {
        let parsed = http_parse_range(
            range,
            client_range.if_range,
            total_content_length.get(),
            cache_time,
            upstream_resp.etag.as_deref(),
        );
        if matches!(parsed, ParsedRange::Invalid) {
            // Same as the streaming path: RFC 9110 says ignore and serve the
            // whole entity, but a client expecting a resume gets everything.
            warn_once_or_debug!(
                "splice proxy: ignoring malformed Range header `{}` from client {}; serving the full file",
                range.escape_debug(),
                conn_details.client
            );
        }
        parsed
    });

    let Some(range_plan) = resolve_client_range(
        client,
        client_range_result,
        total_content_length.get(),
        "volatile 416 response",
    )
    .await?
    else {
        return Ok(());
    };

    let Some(mut target) = prepare_cache_target(
        client,
        conn_details,
        upstream_resp,
        partial_file::PartialDownload::Volatile,
        0,
        total_content_length,
        ibarrier,
        "volatile quota 503",
    )
    .await?
    else {
        return Ok(());
    };

    let start = PreciseInstant::now();

    // The whole body is already buffered in memory, so — unlike the streaming
    // path (`splice_proxy_drive`) — the cache can be fully persisted BEFORE
    // serving the client. Caching costs nothing here and must not depend on the
    // client write, so a late client-write failure no longer discards an
    // already-downloaded body (late joiners and future requests keep it).

    // Write the full body to the cache temp file (best-effort).
    // `tokio::fs::File::write_all` only queues the write on the blocking
    // pool; the follow-up `flush` waits for it, so a failure (e.g. disk full)
    // surfaces here -- `sync_all` below never reports a deferred write error,
    // and without the flush a truncated file would be committed as a success.
    let write_res = match target.tempfile.write_all(&body).await {
        Ok(()) => target.tempfile.flush().await,
        Err(err) => Err(err),
    };
    let cache_write_ok = match write_res {
        Ok(()) => true,
        Err(err) => {
            metrics::CACHE_IO_FAILURE.increment();
            error!(
                "splice proxy: failed to write volatile body to cache file `{}`; serving the buffered body to the client without caching it:  {}",
                target.temppath.display(),
                ErrorReport(&err)
            );
            false
        }
    };

    // Persist via rename+commit, only if the body reached the temp file. When
    // the write failed, the barrier is dropped without a rename at the end of
    // the function — its Drop records the terminal aborted state, correct
    // since nothing is on disk for late joiners to serve.
    let committed = if cache_write_ok {
        target.dbarrier.ping();
        commit_and_record(
            target,
            conn_details,
            original_uri_path,
            total_content_length,
            start,
        )
        .await
    } else {
        drop(target.tempfile);
        None
    };

    // Serve the client from the in-memory body. The cache is already persisted
    // (best-effort above), so an early return on a client write failure no
    // longer loses the downloaded body.

    // Cork to coalesce headers + body into fewer TCP segments.
    let cork = CorkGuard::new_optional(client.stream);

    rates.t_client_first = write_splice_response_headers(
        client,
        conn_details,
        upstream_resp,
        &range_plan,
        "volatile response headers",
    )
    .await?;

    // Send body (range-filtered if needed) to client.
    #[expect(clippy::cast_possible_truncation, reason = "body capped at 1 MiB")]
    let body_slice = &body[range_plan.start as usize..range_plan.end() as usize];
    {
        let config = global_config();
        let mut volatile_rc = config
            .min_download_rate
            .map(|rate| RateChecker::with_timeframe(rate, config.rate_check_timeframe));
        write_all_to_stream_rated(
            client.stream,
            body_slice,
            &mut volatile_rc,
            RateCheckDirection::Client,
            config.http_timeout,
        )
        .await
        .map_err(|err| SpliceProxyError::AfterHeader {
            phase: "volatile body to client",
            side: AfterHeaderSide::Client(err),
        })?;
        metrics::BYTES_SERVED_SPLICE.increment_by(body_slice.len() as u64);
        rates.client_bytes_sent += body_slice.len() as u64;
    }
    rates.t_client_done = PreciseInstant::now();

    drop(cork);

    // The client was fully served (an early return above skips these).
    metrics::SERVED_SPLICE.increment();
    metrics::SERVED_TOTAL.increment();

    if let Some(elapsed) = committed {
        log_splice_completion(
            conn_details,
            conn_label,
            &rates,
            total_content_length.get(),
            0,
            CompletionClient::Served {
                bytes: range_plan.len,
            },
        );

        // Record delivery in database.
        record_delivery(
            conn_details,
            total_content_length,
            elapsed,
            range_plan.is_partial(),
        )
        .await;
    }

    Ok(())
}
