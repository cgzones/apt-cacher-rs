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
//! Buffered bodies use the same cache writer as the streaming path, with
//! commit-time verification instead of an incremental digest.

use std::num::NonZero;

use http::StatusCode;
use tracing::debug;

use crate::active_downloads::Declined;
use crate::cache_conditional::{RangeRequestHeaders, ServeParams};
use crate::cache_layout::ConnectionDetails;
use crate::guards::{Consequence, InitBarrier};
use crate::partial_file;
use crate::precise_instant::PreciseInstant;
use crate::rate_checker::RateChecker;
use crate::sendfile_conn::write_all_to_stream_rated_counted;
use crate::tcp_cork_guard::CorkGuard;
use crate::transfer_error::{DeliveryFailure, EndsDelivery, ReportedDelivery};
use crate::upstream_head::BodyFraming;
use crate::{
    client_counter, global_config, limits::VOLATILE_UNKNOWN_CONTENT_LENGTH_UPPER, metrics,
    warn_once,
};

use super::commit::{CommitTail, Committed, CompletionBytes, CompletionClient, Served};
use super::http::UpstreamResponse;
use super::upstream::{ConnLabel, ResponseBody};
use super::{
    ClientConn, HeadValidators, RateTimestamps, SpliceProxyError, SpliceProxyOutcome,
    prepare_cache_target, write_splice_response_headers,
};

/// Handle the full lifecycle for volatile files whose upstream response has no
/// Content-Length.  The entire body is buffered into memory (up to 1 MiB),
/// then served to the client and cached, bypassing splice(2).
#[expect(
    clippy::too_many_arguments,
    reason = "lifecycle function threading full context"
)]
pub(super) async fn handle_volatile_buffered_download(
    upstream: ResponseBody,
    client: ClientConn<'_>,
    conn_details: &ConnectionDetails,
    upstream_resp: &UpstreamResponse,
    body_prefix: &[u8],
    ibarrier: InitBarrier,
    client_range: RangeRequestHeaders<'_>,
    conn_label: ConnLabel,
) -> Result<SpliceProxyOutcome, SpliceProxyError> {
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
    // Boxed for size, not for the runner: `read_to_vec` carries the whole
    // buffered body state, and inlining it into the connection future pushes
    // `sendfile_conn::try_sendfile_request` past `clippy::large_futures`.
    let (mut ibarrier, body) = ibarrier
        .run(async |_barrier| {
            Box::pin(
                upstream_resp
                    .framing
                    .read_to_vec(upstream, body_prefix, max_bytes),
            )
            .await
            .map_err(Into::into)
        })
        .await
        .map_err(SpliceProxyError::ReportedBeforeHeader)?;

    let mut rates = RateTimestamps::new(upstream_resp.request_sent_at);

    let Some(total_content_length) = NonZero::new(body.len() as u64) else {
        debug!(
            "splice proxy: zero-length volatile body for {} from mirror {}",
            conn_details.debname, conn_details.mirror
        );
        let _settled = ibarrier.decline(Declined::EmptyVolatileBody).await;
        client
            .write_invalid(
                StatusCode::BAD_GATEWAY,
                "zero-length body",
                None,
                "volatile zero-body 502",
            )
            .await?;
        return Ok(SpliceProxyOutcome::Served);
    };

    debug!(
        "splice proxy{conn_label}: buffered volatile download of {} from mirror {} for client {} ({} bytes)...",
        conn_details.debname, conn_details.mirror, conn_details.client, total_content_length
    );

    let Some((target, range_plan)) = prepare_cache_target(
        client,
        conn_details,
        upstream_resp,
        partial_file::PartialDownload::Volatile,
        0,
        total_content_length,
        ibarrier,
        "volatile quota 503",
        client_range,
        "volatile 416 response",
        super::body::CacheWriteMode::Userspace(None),
    )
    .await?
    else {
        return Ok(SpliceProxyOutcome::Served);
    };

    let start = PreciseInstant::now();

    // The whole body is already buffered in memory, so — unlike the streaming
    // path (`splice_proxy_drive`) — the cache can be fully persisted BEFORE
    // serving the client. Caching costs nothing here and must not depend on the
    // client write, so a late client-write failure no longer discards an
    // already-downloaded body (late joiners and future requests keep it).

    // Write the full body to the cache temp file (best-effort).
    // `Abandon`, not `CloseConnection`: the body is already in memory, so a
    // failed cache write loses only the download -- the client is served
    // below and the connection survives.
    // The head is written after the commit consumed the target: keep the
    // validator it settled on.
    let validators = target.validators.clone();
    let cache_write = super::write_body_prefix_to_cache(target, &body, Consequence::Abandon).await;

    // Persist via rename+commit, only if the body reached the temp file. When
    // the write failed, the target went with the failure: its barrier
    // published the terminal aborted state (correct, since nothing is on disk
    // for late joiners to serve) and gave the `max_upstream_downloads` slot
    // back with the entry, so the client write below holds neither.
    let committed = match cache_write {
        Ok(target) => {
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
        }
        Err(_reported) => None,
    };

    // Serve the client from the in-memory body. The cache is already persisted
    // (best-effort above), so a client write failure no longer loses the
    // downloaded body -- and a cached download reports its completion line
    // either way, "Cached ..." for a client that did not get it all, the same
    // as the streaming tail's `Aborted` arm.
    let served = serve_buffered(
        client,
        conn_details,
        upstream_resp,
        &range_plan,
        &validators,
        &body,
        &mut rates,
    )
    .await;

    let (client, outcome) = match served {
        Ok(()) => {
            metrics::SERVED_SPLICE.increment();
            metrics::SERVED_TOTAL.increment();
            let served = Served {
                bytes: range_plan.content_length,
                partial: range_plan.is_partial(),
            };
            (CompletionClient::Served(served), SpliceProxyOutcome::Served)
        }
        // The write concluded its own failure; the connection closes without
        // another line.
        Err(reported) => (
            CompletionClient::Aborted(reported),
            SpliceProxyOutcome::ClientLost,
        ),
    };
    if let Some(committed) = committed {
        Committed::report(committed, &rates, client).await;
    }
    Ok(outcome)
}

/// Phase tag of the buffered path's head write.
const HEAD_PHASE: &str = "volatile response headers";
/// Phase tag of the buffered path's body write.
const BODY_PHASE: &str = "volatile body";

/// Write the response head and the range-filtered slice of the buffered body
/// to the client. Ends the client-rate window on every exit, so the
/// completion line's client segment is right for a lost client too.
async fn serve_buffered(
    client: ClientConn<'_>,
    conn_details: &ConnectionDetails,
    upstream_resp: &UpstreamResponse,
    range_plan: &ServeParams,
    validators: &HeadValidators,
    body: &[u8],
    rates: &mut RateTimestamps,
) -> Result<(), ReportedDelivery> {
    // Cork to coalesce headers + body into fewer TCP segments.
    let cork = CorkGuard::new_optional(client.stream);

    let written = write_buffered_response(
        client,
        conn_details,
        upstream_resp,
        range_plan,
        validators,
        body,
        rates,
    )
    .await;
    rates.t_client_done = PreciseInstant::now();

    drop(cork);
    written
}

/// The one sink for either client write of this path; the failure's type
/// decides what it counts (a head counts nothing).
fn conclude_write(
    conn_details: &ConnectionDetails,
    phase: &'static str,
    failure: impl EndsDelivery,
) -> ReportedDelivery {
    failure.conclude(format_args!(
        "splice proxy: failed to write {phase} to client {} for {} from mirror {}; closing the connection",
        conn_details.client, conn_details.debname, conn_details.mirror,
    ))
}

/// The two client writes of [`serve_buffered`], split out so that function
/// can time and uncork both exits in one place.
async fn write_buffered_response(
    client: ClientConn<'_>,
    conn_details: &ConnectionDetails,
    upstream_resp: &UpstreamResponse,
    range_plan: &ServeParams,
    validators: &HeadValidators,
    body: &[u8],
    rates: &mut RateTimestamps,
) -> Result<(), ReportedDelivery> {
    rates.t_client_first = write_splice_response_headers(
        client,
        conn_details,
        upstream_resp,
        range_plan,
        validators,
        HEAD_PHASE,
    )
    .await
    .map_err(|failure| conclude_write(conn_details, HEAD_PHASE, failure))?;

    #[expect(clippy::cast_possible_truncation, reason = "body capped at 1 MiB")]
    let body_slice = &body[range_plan.content_start as usize..range_plan.content_end() as usize];
    let config = global_config();
    let mut volatile_rc = RateChecker::from_config(config);
    let before = rates.client_bytes_sent;
    let delivered = write_all_to_stream_rated_counted(
        client.stream,
        body_slice,
        &mut volatile_rc,
        config.http_timeout,
        &mut rates.client_bytes_sent,
    )
    .await;
    metrics::BYTES_SERVED_SPLICE.increment_by(rates.client_bytes_sent - before);
    delivered
        .map_err(|err| conclude_write(conn_details, BODY_PHASE, DeliveryFailure::from(err)))?;
    Ok(())
}
