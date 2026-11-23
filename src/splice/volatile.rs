//! Buffered download path for volatile responses without `Content-Length`:
//! [`handle_volatile_buffered_download`] reads the whole body into memory (up
//! to 1 MiB), serves it to the client and caches it, bypassing splice(2).
//!
//! The body lands in the temp file *before* the client is written to, so
//! caching it never depends on the client write succeeding. The commit
//! (`fsync`, verify + rename, the `Download` row) does not delay the response
//! either: it is the spawned `CommitTail` task, started with
//! `CommitTail::spawn_before_serving` right before the response head goes
//! out. As with every spawned commit, a completed response does not prove
//! the cache file exists yet. The upstream connection goes back to the pool
//! the moment the body is read, and the download's `max_upstream_downloads`
//! slot at `CacheTarget::begin_rename`, both before the client write; the
//! completion line and the `Delivery` row wait in the tail for the client's
//! fate (`commit::ClientVerdict::send`).

use std::num::NonZero;

use tracing::debug;

use crate::active_downloads::Declined;
use crate::cache_conditional::{RangeRequestHeaders, ServeParams};
use crate::cache_layout::ConnectionDetails;
use crate::guards::{Consequence, InitBarrier};
use crate::partial_file;
use crate::precise_instant::PreciseInstant;
use crate::tcp_cork_guard::CorkGuard;
use crate::transfer_error::{DeliveryFailure, EndsDelivery, ReportedDelivery};
use crate::{client_counter, limits::VOLATILE_UNKNOWN_CONTENT_LENGTH_UPPER, metrics};

use super::commit::{CompletionBytes, CompletionClient, Served};
use super::http::UpstreamResponse;
use super::upstream::{ConnLabel, ResponseBody};
use super::{
    ClientConn, HeadValidators, RateTimestamps, SpliceProxyError, SpliceProxyOutcome,
    prepare_cache_target, write_client_bytes, write_splice_response_headers,
};

/// Handle the full lifecycle for volatile files whose upstream response has no
/// Content-Length; see the module doc.
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
    prev_file_size: u64,
    ibarrier: InitBarrier,
    client_range: RangeRequestHeaders<'_>,
    conn_label: ConnLabel,
) -> Result<SpliceProxyOutcome, SpliceProxyError> {
    let max_bytes: usize = VOLATILE_UNKNOWN_CONTENT_LENGTH_UPPER
        .get()
        .try_into()
        .expect("constant fits"); // TODO: const conversion once stable

    // The buffered path bypasses the body loops that normally hold this, and
    // would otherwise undercount `ACTIVE_CLIENT_DOWNLOADS`.
    let _client_count = client_counter::ClientDownload::new();

    // Buffer the entire body into memory: chunked or close-delimited, since
    // the planner sends every length-delimited body to the splice loops.
    // Boxed for size, not for the runner: `read_to_vec` carries the whole
    // buffered body state, and inlining it into the connection future pushes
    // `sendfile_conn::try_sendfile_request` past `clippy::large_futures`.
    let (mut ibarrier, mut body) = ibarrier
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

    let mut rates = RateTimestamps::new(upstream_resp.request_sent_at, upstream_resp.head_at);

    let Some(total_content_length) = NonZero::new(body.len() as u64) else {
        debug!(
            "splice proxy: zero-length volatile body for {} from mirror {}",
            conn_details.debname, conn_details.mirror
        );
        client
            .decline(
                &mut ibarrier,
                Declined::EmptyVolatileBody,
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
        partial_file::PartialDownload::Scratch,
        0,
        total_content_length,
        prev_file_size,
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

    // `Abandon`, not `CloseConnection`: the body is already in memory, so a
    // failed cache write loses only the download -- the client is served
    // below and the connection survives.
    // The head is written after the commit consumed the target: keep the
    // validator it settled on.
    let validators = target.validators.clone();
    let cache_write =
        super::write_buffered_body_to_cache(target, &mut body, Consequence::Abandon).await;

    // When the cache write failed, the target went with the failure: its
    // barrier published the terminal aborted state (nothing is on disk for
    // late joiners to serve) and gave the `max_upstream_downloads` slot back
    // with the entry.
    let verdict = match cache_write {
        Ok(target) => target
            .begin_rename(
                conn_details.clone(),
                conn_label,
                CompletionBytes {
                    total: total_content_length,
                    upstream: total_content_length.get(),
                    resume_offset: 0,
                },
                start,
            )
            .await
            .ok()
            .map(|tail| tail.spawn_before_serving(rates)),
        Err(_reported) => None,
    };

    // A client write failure does not lose the downloaded body, and a cached
    // download reports its completion line either way ("Cached ..." for a
    // client that did not get it all). A failed commit logged its own cause
    // in the tail and reports nothing; the connection is unaffected.
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
                bytes: range_plan.content_length(),
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
    if let Some(verdict) = verdict {
        verdict.send(rates, client);
    }
    Ok(outcome)
}

const HEAD_PHASE: &str = "volatile response headers";
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

    let written = async {
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
        let body_slice =
            &body[range_plan.content_start() as usize..range_plan.content_end() as usize];
        write_client_bytes(client.stream, body_slice, rates)
            .await
            .map_err(|err| conclude_write(conn_details, BODY_PHASE, DeliveryFailure::from(err)))
    }
    .await;
    rates.t_client_done = PreciseInstant::now();

    drop(cork);
    written
}

/// The failure's type decides what it counts (a head counts nothing).
fn conclude_write(
    conn_details: &ConnectionDetails,
    phase: &'static str,
    failure: impl EndsDelivery,
) -> ReportedDelivery {
    failure.conclude(Some(&conn_details.client), format_args!(
        "splice proxy: failed to write {phase} to client {} for {} from mirror {}; closing the connection",
        conn_details.client, conn_details.debname, conn_details.mirror,
    ))
}
