//! The one hyper body wrapper that does per-delivery accounting.
//!
//! Every hyper body that ships bytes to a client is wrapped in
//! [`AccountedBody`]: it holds the `ACTIVE_CLIENT_DOWNLOADS` counter for the
//! body's lifetime, counts data bytes, remembers whether the stream ended
//! cleanly or with which error, and on `Drop` runs the completion
//! bookkeeping for its [`Subject`] - `delivery::finish_cached_serve` for
//! cached files, the passthrough summary for the simple proxy. "Fully
//! delivered" (the `SERVED_*` credit) is decided here: every promised byte
//! shipped for a cached file, clean end of stream for a passthrough, and no
//! error surfaced either way.

use std::{fmt::Display, pin::Pin, task::Poll};

use bytes::Buf as _;
use http_body::{Body, Frame, SizeHint};
use pin_project::{pin_project, pinned_drop};
use tracing::info;

use crate::{
    cache_layout::ConnectionDetails,
    client_counter::ClientDownload,
    client_info::ClientInfo,
    database_task::{DatabaseCommand, send_db_command_nonblocking},
    delivery::{AbortCause, DeliveryEnd, Mechanism, Role, ServeOutcome, finish_cached_serve},
    humanfmt::HumanFmt,
    metrics,
    precise_instant::PreciseInstant,
    rate_log,
};

/// What the body delivers, i.e. which completion line and metrics apply.
pub(crate) enum Subject {
    /// A cached (or in-progress) file: `Served cached file ... via <mech>`,
    /// a `deliveries` row on completion.
    Cached {
        conn_details: ConnectionDetails,
        mechanism: Mechanism,
        /// Bytes the response promised (after Range trimming).
        size: u64,
        /// A 206 delivery.
        partial: bool,
    },
    /// An uncached passthrough: `simple proxy: passed through ...`, no DB row.
    Passthrough {
        host: String,
        path: String,
        client: ClientInfo,
        request_received_at: PreciseInstant,
        request_sent: PreciseInstant,
    },
}

/// The first error the inner body surfaced, kept for the abort line.
struct BodyFailure {
    /// Rendered eagerly: the inner error does not outlive its poll.
    reason: String,
    /// [`AccountedBody::peer_disconnect_check`]'s verdict, which demotes the
    /// abort line to INFO.
    peer_disconnect: bool,
}

#[pin_project(PinnedDrop)]
pub(crate) struct AccountedBody<B: Body> {
    #[pin]
    inner: B,
    subject: Option<Subject>,
    transferred: u64,
    end_of_stream: bool,
    /// Sticky: vetoes the `SERVED_*` credit even if a later poll reaches
    /// `Ready(None)`.
    error: Option<BodyFailure>,
    peer_disconnect_check: fn(&B::Error) -> bool,
    start: PreciseInstant,
    _counter: ClientDownload,
}

impl<B: Body> AccountedBody<B> {
    /// Wrap `inner`; bumps the subject's `REQUESTS_*` counter and takes the
    /// active-download slot. `peer_disconnect_check` classifies inner errors
    /// for the abort line's severity (pass `|_| false` when the transport
    /// cannot tell).
    #[must_use]
    pub(crate) fn new(
        inner: B,
        subject: Subject,
        peer_disconnect_check: fn(&B::Error) -> bool,
    ) -> Self {
        match &subject {
            Subject::Cached { mechanism, .. } => mechanism.requests().increment(),
            Subject::Passthrough { .. } => metrics::REQUESTS_PASSTHROUGH.increment(),
        }
        Self {
            inner,
            subject: Some(subject),
            transferred: 0,
            end_of_stream: false,
            error: None,
            peer_disconnect_check,
            start: PreciseInstant::now(),
            _counter: ClientDownload::new(),
        }
    }
}

impl<B> Body for AccountedBody<B>
where
    B: Body,
    B::Error: Display,
{
    type Data = B::Data;
    type Error = B::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.project();
        let result = this.inner.poll_frame(cx);
        match &result {
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(data) = frame.data_ref() {
                    *this.transferred += data.remaining() as u64;
                }
            }
            Poll::Ready(Some(Err(err))) => {
                if this.error.is_none() {
                    *this.error = Some(BodyFailure {
                        reason: err.to_string(),
                        peer_disconnect: (this.peer_disconnect_check)(err),
                    });
                }
            }
            Poll::Ready(None) => *this.end_of_stream = true,
            Poll::Pending => {}
        }
        result
    }

    #[inline]
    fn size_hint(&self) -> SizeHint {
        match &self.subject {
            // The promised length is known exactly; the inner reader may
            // not advertise one (a `StreamBody` over a file reader).
            Some(Subject::Cached { size, .. }) => match size.checked_sub(self.transferred) {
                Some(remaining) => SizeHint::with_exact(remaining),
                None => SizeHint::default(),
            },
            Some(Subject::Passthrough { .. }) | None => self.inner.size_hint(),
        }
    }

    #[inline]
    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }
}

#[pinned_drop]
impl<B: Body> PinnedDrop for AccountedBody<B> {
    fn drop(self: Pin<&mut Self>) {
        let transferred = self.transferred;
        let end_of_stream = self.end_of_stream;
        let elapsed = self.start.elapsed();
        let this = self.project();
        let error = this.error.take();
        let subject = this.subject.take().expect("set in new()");
        // Logging is synchronous and the DB enqueue has a sync fast path -
        // no per-request task spawn needed here.
        match subject {
            Subject::Cached {
                conn_details,
                mechanism,
                size,
                partial,
            } => {
                mechanism.bytes_served().increment_by(transferred);
                // hyper stops polling once the promised Content-Length is
                // out, so `end_of_stream` is not a reliable signal here; the
                // promised byte count is.
                let end = if transferred == size && error.is_none() {
                    DeliveryEnd::Complete
                } else {
                    DeliveryEnd::Aborted(error.as_ref().map(|failure| AbortCause {
                        reason: &failure.reason,
                        peer_disconnect: failure.peer_disconnect,
                    }))
                };
                let outcome = ServeOutcome {
                    size,
                    transferred,
                    partial,
                    elapsed,
                    end,
                };
                if let Some(cmd) =
                    finish_cached_serve(&conn_details, mechanism, Role::Cached, outcome)
                {
                    send_db_command_nonblocking(DatabaseCommand::Transfer(cmd));
                }
            }
            Subject::Passthrough {
                host,
                path,
                client,
                request_received_at,
                request_sent,
            } => {
                metrics::BYTES_SERVED_PASSTHROUGH.increment_by(transferred);
                let in_time = request_received_at.elapsed();
                if end_of_stream && error.is_none() {
                    metrics::SERVED_PASSTHROUGH.increment();
                    metrics::SERVED_TOTAL.increment();
                    info!(
                        "simple proxy: passed through {path} from host {host} for client {client} in {} ({}, {})",
                        HumanFmt::Time(in_time),
                        rate_log::upstream_segment(transferred, request_sent.elapsed()),
                        rate_log::client_segment(transferred, elapsed),
                    );
                } else {
                    info!(
                        "simple proxy: aborted passthrough of {path} from host {host} for client {client} in {} ({})",
                        HumanFmt::Time(in_time),
                        rate_log::client_disconnect_segment(transferred, elapsed),
                    );
                }
            }
        }
    }
}
