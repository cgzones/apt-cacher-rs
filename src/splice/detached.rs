//! The client-less half of the parallel-download hack in splice builds.
//!
//! `splice_proxy`'s nudge gate answers the client with a `429` plus
//! `Retry-After` (see `crate::parallel_hack`) and hands everything the
//! download still needs to a [`DetachedDownload`], which finishes it on its
//! own task. The client's retry late-joins through `ActiveDownloads::attach`
//! like any other concurrent request for an in-flight download.
//!
//! `DetachedDownload::run` mirrors the tail of `splice_proxy` from the
//! body-prefix step on, minus every client write: the body loops run in
//! `ClientStatus::Absent` (see `super::body`), and the commit and the
//! completion line are the same `super::commit::CommitTail`, awaited in
//! place since this task is already off the connection.

use bytes::BytesMut;

use crate::cache_layout::ConnectionDetails;
use crate::guards::Consequence;
use crate::precise_instant::PreciseInstant;

use super::body::{BodyClient, ClientEnd};
use super::commit::{CompletionBytes, CompletionClient};
use super::upstream::{ConnLabel, ResponseBody};
use super::{
    BodyTransferred, CacheTarget, RateTimestamps, log_download_start, transfer_body,
    write_body_prefix_to_cache,
};
use crate::cache_conditional::ServeParams;

/// A download whose client has been nudged away: everything
/// `splice_proxy` had in hand at the gate, owned rather than borrowed,
/// so it can outlive the connection task.
pub(super) struct DetachedDownload {
    pub(super) upstream: ResponseBody,
    /// The head-read buffer; the body prefix is `header_buf[header_end..]`.
    pub(super) header_buf: BytesMut,
    pub(super) header_end: usize,
    pub(super) target: CacheTarget,
    pub(super) conn_details: ConnectionDetails,
    pub(super) conn_label: ConnLabel,
    pub(super) bytes: CompletionBytes,
    pub(super) splice_count: u64,
    /// Start of the upstream-rate window: when the upstream request went out.
    pub(super) request_sent_at: PreciseInstant,
    /// When its response head was parsed: the throughput window's start.
    pub(super) head_at: PreciseInstant,
}

/// The serve plan of a client-less transfer: a zero `content_length` makes
/// `transfer_body`'s range arithmetic yield `send == 0`, so the body loops
/// take their cache-only branch for every chunk.
const NO_CLIENT_RANGE: ServeParams = ServeParams::full(0);

impl DetachedDownload {
    /// Fire-and-forget: the connection task returns to its next request
    /// while this one finishes the download.
    pub(super) fn spawn(self) {
        tokio::task::spawn(self.run());
    }

    async fn run(self) {
        let Self {
            mut upstream,
            header_buf,
            header_end,
            target,
            conn_details,
            conn_label,
            bytes,
            splice_count,
            request_sent_at,
            head_at,
        } = self;

        let start = PreciseInstant::now();
        let mut rates = RateTimestamps::new(request_sent_at, head_at);

        log_download_start(
            &conn_details,
            conn_label,
            bytes.resume_offset,
            bytes.total,
            true,
        );

        let target = match write_body_prefix_to_cache(
            target,
            &header_buf[header_end..],
            Consequence::Abandon,
        )
        .await
        {
            Ok(target) => target,
            // The runner concluded the failure and published it to readers;
            // a permanent partial stays on disk for a later resume.
            Err(_reported) => return,
        };

        drop(header_buf);

        let target = match transfer_body(
            &mut upstream,
            BodyClient::Absent,
            target,
            splice_count,
            &NO_CLIENT_RANGE,
            None,
            &mut rates,
            Consequence::Abandon,
        )
        .await
        {
            Ok(BodyTransferred { target, client }) => {
                debug_assert!(
                    matches!(client, ClientEnd::Absent),
                    "a client-less transfer has no client to demote or lose"
                );
                target
            }
            Err(_reported) => {
                return;
            }
        };

        upstream.complete();

        // A commit failure already logged its cause and dropped the barrier;
        // nothing is cached, so no DB rows and no completion line. Upstream
        // side only: no client was ever served, so there is no `SERVED_*` /
        // `BYTES_SERVED_SPLICE` bump and no `Delivery` row.
        if let Ok(tail) = target
            .begin_rename(conn_details, conn_label, bytes, start)
            .await
        {
            tail.finish(rates, CompletionClient::Absent).await;
        }
    }
}
