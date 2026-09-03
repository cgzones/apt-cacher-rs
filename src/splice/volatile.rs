//! Buffered download path for volatile responses without `Content-Length`:
//! [`handle_volatile_buffered_download`] reads the whole body into memory (up
//! to 1 MiB), serves it to the client and caches it, bypassing splice(2).
//! Shares the response-head, cache-target, commit and completion-log helpers
//! with the drive in `mod.rs`.
//!
//! It commits in the opposite order to the streaming drive, deliberately: this
//! path awaits `CommitTail::commit` inline *before* serving the client, where
//! the streaming drive commits alongside client settlement. The body is buffered in
//! memory here, so caching it costs the client nothing and must not be made
//! to depend on the client write succeeding. The upstream connection goes
//! back to the pool the moment the body is read, and the download's
//! `max_upstream_downloads` slot at `CacheTarget::begin_rename`, both before
//! the commit starts rather than whenever the caller's frame happens to end;
//! the completion line and the `Delivery` row wait for the client write
//! ([`Committed::report`]).
//!
//! It also passes `None` for `prepare_cache_target`'s `hasher`: the buffered
//! body goes straight to the temp file, past the two sites that advance a
//! `StreamHasher`, so any hasher handed to this path would be finalised over no
//! input and fail verification for every registry-backed `Packages` fetch that
//! arrives without a `Content-Length`. This path's commit re-reads and hashes
//! the finished file instead.

use std::num::NonZero;

use http::StatusCode;
use tracing::{debug, error};

use crate::cache_conditional::{RangeRequestHeaders, ServeParams};
use crate::cache_layout::ConnectionDetails;
use crate::error::ErrorReport;
use crate::guards::InitBarrier;
use crate::http_range::HttpDate;
use crate::partial_file;
use crate::precise_instant::PreciseInstant;
use crate::rate_checker::{RateCheckDirection, RateChecker};
use crate::sendfile_conn::write_all_to_stream_rated;
use crate::tcp_cork_guard::CorkGuard;
use crate::{
    client_counter, global_config, limits::VOLATILE_UNKNOWN_CONTENT_LENGTH_UPPER, metrics,
    warn_once, warn_once_or_info_logged,
};

use super::commit::{CommitTail, Committed, CompletionBytes, CompletionClient, Served};
use super::http::{BodyFraming, UpstreamResponse};
use super::upstream::{ConnLabel, PoolGuard};
use super::{
    ClientConn, RateTimestamps, SpliceProxyError, UpstreamFailure, prepare_cache_target,
    resolve_client_range, write_all_flushed, write_splice_response_headers,
};

/// Handle the full lifecycle for volatile files whose upstream response has no
/// Content-Length.  The entire body is buffered into memory (up to 1 MiB),
/// then served to the client and cached, bypassing splice(2).
#[expect(
    clippy::too_many_arguments,
    reason = "lifecycle function threading full context"
)]
pub(super) async fn handle_volatile_buffered_download(
    mut upstream: PoolGuard,
    client: ClientConn<'_>,
    conn_details: &ConnectionDetails,
    upstream_resp: &UpstreamResponse,
    body_prefix: &[u8],
    ibarrier: InitBarrier<'_>,
    client_range: RangeRequestHeaders<'_>,
    conn_label: ConnLabel,
) -> Result<(), SpliceProxyError> {
    let max_bytes: usize = VOLATILE_UNKNOWN_CONTENT_LENGTH_UPPER
        .get()
        .try_into()
        .expect("constant fits"); // TODO: const conversion once stable

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
        .read_to_vec(&mut upstream, body_prefix, max_bytes)
        .await
        .map_err(|err| {
            let logged = warn_once_or_info_logged!(
                "splice proxy: volatile buffered download failed for {}; returning 502:  {}",
                conn_details.debname,
                ErrorReport(&err)
            );
            SpliceProxyError::Upstream(UpstreamFailure { err, logged })
        })?;
    // The whole body is in hand, so the connection is done: `PoolGuard::drop`
    // returns it to the pool (or discards it, for the close-delimited framing
    // `read_to_vec` poisons) before the commit and the client write below.
    drop(upstream);

    let mut rates = RateTimestamps::new(upstream_resp.request_sent_at);

    let Some(total_content_length) = NonZero::new(body.len() as u64) else {
        debug!(
            "splice proxy: zero-length volatile body for {} from mirror {}",
            conn_details.debname, conn_details.mirror
        );
        client
            .write_invalid(
                StatusCode::BAD_GATEWAY,
                "zero-length body",
                None,
                "volatile zero-body 502",
            )
            .await?;
        return Ok(());
    };

    debug!(
        "splice proxy{conn_label}: buffered volatile download of {} from mirror {} for client {} ({} bytes)...",
        conn_details.debname, conn_details.mirror, conn_details.client, total_content_length
    );

    // The body was just fetched: an `If-Range` date is compared against now.
    let Some(range_plan) = resolve_client_range(
        client,
        conn_details,
        client_range,
        total_content_length.get(),
        HttpDate::now(),
        upstream_resp.etag.as_deref(),
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
        // No incremental digest: the buffered body below is written straight
        // to `tempfile`, bypassing the two sites that feed a `StreamHasher`.
        // A hasher here would be finalised over no input at all and fail
        // verification for every registry-backed `Packages` fetch that lands
        // on this path.
        None,
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
    let cache_write_ok = match write_all_flushed(&mut target.tempfile, &body).await {
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
    // the write failed, the whole target is dropped here: its barrier records
    // the terminal aborted state (correct, since nothing is on disk for late
    // joiners to serve) and gives the `max_upstream_downloads` slot back with
    // the entry, so the client write below holds neither.
    let committed = if cache_write_ok {
        CommitTail::new(
            target.begin_rename().await,
            conn_details,
            conn_label,
            CompletionBytes {
                total: total_content_length,
                upstream: total_content_length.get(),
                resume_offset: 0,
            },
            start,
        )
        .commit()
        .await
    } else {
        drop(target);
        None
    };

    // Serve the client from the in-memory body. The cache is already persisted
    // (best-effort above), so a client write failure no longer loses the
    // downloaded body -- and a cached download reports its completion line
    // either way, "Cached ..." for a client that did not get it all, the same
    // as the streaming tail's `Lost` arm.
    let served = serve_buffered(
        client,
        conn_details,
        upstream_resp,
        &range_plan,
        &body,
        &mut rates,
    )
    .await;

    if let Some(committed) = committed {
        let client = if served.is_ok() {
            CompletionClient::Served(Served {
                bytes: range_plan.content_length,
                partial: range_plan.is_partial(),
            })
        } else {
            CompletionClient::Lost
        };
        Committed::report(committed, &rates, client).await;
    }

    served?;

    // The client was fully served (the `?` above skips these).
    metrics::SERVED_SPLICE.increment();
    metrics::SERVED_TOTAL.increment();

    Ok(())
}

/// Write the response head and the range-filtered slice of the buffered body
/// to the client. Ends the client-rate window on every exit, so the
/// completion line's client segment is right for a lost client too.
async fn serve_buffered(
    client: ClientConn<'_>,
    conn_details: &ConnectionDetails,
    upstream_resp: &UpstreamResponse,
    range_plan: &ServeParams,
    body: &[u8],
    rates: &mut RateTimestamps,
) -> Result<(), SpliceProxyError> {
    // Cork to coalesce headers + body into fewer TCP segments.
    let cork = CorkGuard::new_optional(client.stream);

    let written =
        write_buffered_response(client, conn_details, upstream_resp, range_plan, body, rates).await;
    rates.t_client_done = PreciseInstant::now();

    drop(cork);
    written
}

/// The two client writes of [`serve_buffered`], split out so that function
/// can time and uncork both exits in one place.
async fn write_buffered_response(
    client: ClientConn<'_>,
    conn_details: &ConnectionDetails,
    upstream_resp: &UpstreamResponse,
    range_plan: &ServeParams,
    body: &[u8],
    rates: &mut RateTimestamps,
) -> Result<(), SpliceProxyError> {
    rates.t_client_first = write_splice_response_headers(
        client,
        conn_details,
        upstream_resp,
        range_plan,
        "volatile response headers",
    )
    .await?;

    #[expect(clippy::cast_possible_truncation, reason = "body capped at 1 MiB")]
    let body_slice = &body[range_plan.content_start as usize..range_plan.content_end() as usize];
    let config = global_config();
    let mut volatile_rc = RateChecker::from_config(config);
    write_all_to_stream_rated(
        client.stream,
        body_slice,
        &mut volatile_rc,
        RateCheckDirection::Client,
        config.http_timeout,
    )
    .await
    .map_err(SpliceProxyError::after_header_client(
        "volatile body to client",
    ))?;
    metrics::BYTES_SERVED_SPLICE.increment_by(body_slice.len() as u64);
    rates.client_bytes_sent += body_slice.len() as u64;
    Ok(())
}
