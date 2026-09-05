//! The client-less half of the parallel-download hack in splice builds.
//!
//! `splice_proxy_drive`'s nudge gate answers the client with a `429` plus
//! `Retry-After` (see `crate::parallel_hack`) and hands everything the
//! download still needs -- the upstream connection, the cache target with its
//! registry entry and quota reservation, the body geometry -- to a
//! [`DetachedDownload`], which finishes it on its own task. The client's retry
//! late-joins through `ActiveDownloads::attach` on the same keep-alive
//! connection, exactly like any other concurrent request for an in-flight
//! download.
//!
//! `DetachedDownload::run` mirrors the tail of `splice_proxy_drive` from the body-prefix
//! step on, minus every client write: the body loops run in
//! `ClientStatus::Absent` (see `super::body`), and a failure is attributed by
//! `BodyTransferError::log_detached` because there is no connection left whose
//! outer arm could report it.
//!
//! Feature coverage falls out of the ownership: the task holds whichever
//! `UpstreamConn` variant the exchange produced, so hyper-less builds are
//! covered without a second code path.

use std::num::NonZero;

use bytes::BytesMut;
use tracing::debug;

use crate::cache_layout::ConnectionDetails;
use crate::precise_instant::PreciseInstant;

use super::upstream::{ConnLabel, PoolGuard, UnconsumedBodyGuard};
use super::{
    BodyTransferFailure, BodyTransferred, CacheTarget, CompletionClient, RateTimestamps,
    commit_and_record, log_splice_completion, transfer_body, write_body_prefix_to_cache,
};
use crate::cache_conditional::ServeParams;

/// A download whose client has been nudged away: everything
/// `splice_proxy_drive` had in hand at the gate, owned rather than borrowed,
/// so it can outlive the connection task.
pub(super) struct DetachedDownload {
    /// Owned upstream connection.
    pub(super) upstream: PoolGuard,
    /// The head-read buffer; the body prefix is `header_buf[header_end..]`.
    pub(super) header_buf: BytesMut,
    pub(super) header_end: usize,
    /// The partial file, its path guard, the destination and the download
    /// barrier (registry entry plus quota reservation).
    pub(super) target: CacheTarget,
    pub(super) conn_details: ConnectionDetails,
    /// The pre-redirect client request path, for the `Origin` row.
    pub(super) original_uri_path: String,
    pub(super) conn_label: ConnLabel,
    pub(super) total_content_length: NonZero<u64>,
    pub(super) body_content_length: NonZero<u64>,
    pub(super) resume_offset: u64,
    pub(super) splice_count: u64,
    /// Start of the upstream-rate window: when the upstream request went out.
    pub(super) request_sent_at: PreciseInstant,
}

/// The serve plan of a client-less transfer: a zero `content_length` makes
/// `transfer_body`'s range arithmetic yield `send == 0`, so the body loops
/// take their cache-only branch for every chunk.
const NO_CLIENT_RANGE: ServeParams = ServeParams::full(0);

impl DetachedDownload {
    /// Fire-and-forget, like the hyper backend's `download_file` spawn: the
    /// connection task returns to its next request while this one finishes
    /// the download.
    pub(super) fn spawn(self) {
        tokio::task::spawn(self.run());
    }

    async fn run(self) {
        let Self {
            mut upstream,
            header_buf,
            header_end,
            mut target,
            conn_details,
            original_uri_path,
            conn_label,
            total_content_length,
            body_content_length,
            resume_offset,
            splice_count,
            request_sent_at,
        } = self;

        // Armed as the very first statement, before anything else in this
        // task can run: the only gap left is the window before the spawned
        // task is ever polled at all (e.g. a runtime shutdown racing the
        // `spawn` call), where the upstream connection is guarded neither
        // here nor by the caller, which already released its own guard.
        // `PoolGuard::check_alive`'s `MSG_PEEK` probe on a pooled connection
        // catches a half-read socket that slipped back in that way.
        let mut upstream_guard = UnconsumedBodyGuard::new(&mut upstream);

        let start = PreciseInstant::now();
        let mut rates = RateTimestamps::new(request_sent_at);

        log_detached_start(
            &conn_details,
            conn_label,
            resume_offset,
            total_content_length,
        );

        if write_body_prefix_to_cache(
            &mut target,
            &header_buf[header_end..],
            "abandoning the download",
        )
        .await
        .is_err()
        {
            // The writer logged the failure with the on-disk path and bumped
            // `CACHE_IO_FAILURE`; dropping `target` here removes the partial
            // and records the abort on the barrier.
            return;
        }

        let target = match transfer_body(
            &mut upstream_guard,
            None,
            target,
            resume_offset,
            body_content_length,
            splice_count,
            &NO_CLIENT_RANGE,
            &mut rates,
        )
        .await
        {
            Ok(BodyTransferred {
                target,
                demoted_handle,
                client_disconnected: _,
            }) => {
                debug_assert!(
                    demoted_handle.is_none(),
                    "a client-less transfer has no client to demote"
                );
                target
            }
            Err(BodyTransferFailure { temppath, err }) => {
                err.log_detached("splice body transfer", &temppath);
                return;
            }
        };

        // The full upstream body is drained: defuse the poison and release
        // its borrow, then let `PoolGuard::drop` return the connection.
        upstream_guard.consumed();
        drop(upstream_guard);
        drop(upstream);

        // A commit failure already logged its cause and dropped the barrier;
        // nothing is cached, so no DB rows and no completion line.
        if commit_and_record(
            target,
            &conn_details,
            &original_uri_path,
            total_content_length,
            start,
        )
        .await
        .is_some()
        {
            // Upstream side only: no client was served, so there is no
            // `SERVED_*` / `BYTES_SERVED_SPLICE` bump and no `Delivery` row.
            log_splice_completion(
                &conn_details,
                conn_label,
                &rates,
                body_content_length.get(),
                resume_offset,
                CompletionClient::Nudged,
            );
        }
    }
}

/// The debug line opening a nudged download's serve.
///
/// Mirrors `log_download_start`'s two shapes, but this download never had a
/// client attached: it says "after nudging client" rather than "serving ...
/// for client", since that client already moved on to its retry.
fn log_detached_start(
    conn_details: &ConnectionDetails,
    conn_label: ConnLabel,
    resume_offset: u64,
    total_content_length: NonZero<u64>,
) {
    if resume_offset > 0 {
        #[expect(clippy::cast_precision_loss, reason = "only for display purpose")]
        let resume_percent = resume_offset as f32 / total_content_length.get() as f32 * 100.0;

        debug!(
            "splice proxy{conn_label}: resuming {} from mirror {} after nudging client {} at byte {} ({:.1}%)...",
            conn_details.debname,
            conn_details.mirror,
            conn_details.client,
            resume_offset,
            resume_percent
        );
    } else {
        debug!(
            "splice proxy{conn_label}: downloading {} from mirror {} after nudging client {}...",
            conn_details.debname, conn_details.mirror, conn_details.client
        );
    }
}
