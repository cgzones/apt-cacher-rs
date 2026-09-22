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

use std::{pin::Pin, task::Poll};

use bytes::Buf as _;
use http_body::{Body, Frame, SizeHint};
use pin_project::{pin_project, pinned_drop};
use tracing::info;

use crate::{
    cache_layout::ConnectionDetails,
    client_counter::ClientDownload,
    client_info::ClientInfo,
    database_task::{DatabaseCommand, send_db_command_nonblocking},
    delivery::{Mechanism, Role, ServeOutcome, finish_cached_serve},
    humanfmt::HumanFmt,
    metrics,
    passthrough_limiter::RelaySlot,
    precise_instant::PreciseInstant,
    rate_log, sticky,
    transfer_error::{DeliveryEnd, DeliveryFailure, EndsDelivery as _},
};

/// What the body delivers, i.e. which completion line and metrics apply.
pub(crate) enum Subject {
    /// A cached (or in-progress) file: `Served cached file ... via <mech>`,
    /// a `deliveries` row on completion.
    Cached {
        conn_details: ConnectionDetails,
        mechanism: Mechanism,
        /// Bytes the response promised (after Range trimming).
        size: Option<u64>,
        role: Role,
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
        /// The `max_passthrough_relays` slot, held until the body is
        /// dropped. Every relay takes one, the cache fetch whose upstream
        /// answer is relayed uncached included: its download slot rides on
        /// the `InitBarrier`, which is gone by the time this body streams.
        relay_slot: RelaySlot,
    },
}

#[pin_project(PinnedDrop)]
pub(crate) struct AccountedBody<B: Body<Error = DeliveryFailure>> {
    #[pin]
    inner: B,
    subject: Option<Subject>,
    transferred: u64,
    end_of_stream: sticky::Bool,
    /// Sticky: vetoes the `SERVED_*` credit even if a later poll reaches
    /// `Ready(None)`.
    error: Option<DeliveryFailure>,
    start: PreciseInstant,
    _counter: ClientDownload,
}

impl<B: Body<Error = DeliveryFailure>> AccountedBody<B> {
    /// Wrap `inner`; bumps the subject's `REQUESTS_*` counter and takes the
    /// active-download slot. Source and client-rate adapters are inside this owner.
    #[must_use]
    pub(crate) fn new(inner: B, subject: Subject) -> Self {
        match &subject {
            Subject::Cached { mechanism, .. } => mechanism.requests().increment(),
            Subject::Passthrough { .. } => metrics::REQUESTS_PASSTHROUGH.increment(),
        }
        Self {
            inner,
            subject: Some(subject),
            transferred: 0,
            end_of_stream: sticky::Bool::new(),
            error: None,
            start: PreciseInstant::now(),
            _counter: ClientDownload::new(),
        }
    }
}

impl<B> Body for AccountedBody<B>
where
    B: Body<Error = DeliveryFailure>,
{
    type Data = B::Data;
    type Error = DeliveryFailure;

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
                    *this.error = Some(err.clone());
                }
            }
            Poll::Ready(None) => {
                this.end_of_stream.set();
            }
            Poll::Pending => {}
        }
        // Hyper erases this error into its connection error's source; the
        // body owner retains the typed cause and reports it on Drop, and the
        // connection handler recognises it there by its concrete type.
        result
    }

    #[inline]
    fn size_hint(&self) -> SizeHint {
        match &self.subject {
            // The promised length is known exactly; the inner reader may
            // not advertise one (a `StreamBody` over a file reader).
            Some(Subject::Cached {
                size: Some(size), ..
            }) => match size.checked_sub(self.transferred) {
                Some(remaining) => SizeHint::with_exact(remaining),
                None => SizeHint::default(),
            },
            Some(Subject::Cached { size: None, .. } | Subject::Passthrough { .. }) | None => {
                self.inner.size_hint()
            }
        }
    }

    #[inline]
    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }
}

#[pinned_drop]
impl<B: Body<Error = DeliveryFailure>> PinnedDrop for AccountedBody<B> {
    fn drop(self: Pin<&mut Self>) {
        let transferred = self.transferred;
        let end_of_stream = self.end_of_stream.get() || self.inner.is_end_stream();
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
                role,
                partial,
            } => {
                mechanism.bytes_served().increment_by(transferred);
                // hyper stops polling once the promised Content-Length is
                // out, so `end_of_stream` is not a reliable signal here; the
                // promised byte count is.
                let end =
                    if size.map_or(end_of_stream, |size| transferred == size) && error.is_none() {
                        DeliveryEnd::Complete
                    } else {
                        DeliveryEnd::Aborted(error.unwrap_or(DeliveryFailure::Cancelled))
                    };
                let outcome = ServeOutcome {
                    size: size.unwrap_or(transferred),
                    transferred,
                    partial,
                    elapsed,
                    end,
                };
                if let Some(cmd) = finish_cached_serve(&conn_details, mechanism, role, outcome) {
                    send_db_command_nonblocking(DatabaseCommand::Transfer(cmd));
                }
            }
            Subject::Passthrough {
                host,
                path,
                client,
                request_received_at,
                request_sent,
                relay_slot,
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
                    let _reported = error.unwrap_or(DeliveryFailure::Cancelled).conclude(format_args!(
                        "simple proxy: aborted passthrough of {path} from host {host} for client {client} in {} ({})",
                        HumanFmt::Time(in_time),
                        rate_log::client_abort_segment(transferred, elapsed),
                    ));
                }
                // Released only now, once the relay can move no more bytes.
                drop(relay_slot);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        channel_body::{ChannelBody, ChannelEvent},
        nonzero, passthrough_limiter,
        test_support::{connection_details, local_client},
        transfer_error::CacheError,
        upstream_head::ContentLength,
    };
    use bytes::Bytes;

    fn subject(size: Option<u64>) -> Subject {
        Subject::Cached {
            conn_details: connection_details("accounted.deb"),
            mechanism: Mechanism::Channel,
            size,
            role: Role::LateJoiner,
            partial: false,
        }
    }

    async fn next(
        body: &mut AccountedBody<ChannelBody>,
    ) -> Option<Result<Frame<Bytes>, DeliveryFailure>> {
        std::future::poll_fn(|cx| Pin::new(&mut *body).poll_frame(cx)).await
    }

    /// A single test owns the process-global DB queue and channel metric deltas.
    /// It checks consumer progress, complete credit, and the sticky error veto.
    #[tokio::test]
    async fn channel_accounting_has_one_consumer_owner() {
        let (db_tx, mut db_rx) = tokio::sync::mpsc::channel(16);
        assert!(
            crate::database_task::DB_TASK_QUEUE_SENDER
                .set(db_tx)
                .is_ok()
        );
        let served_before = metrics::SERVED_CHANNEL.get();
        let bytes_before = metrics::BYTES_SERVED_CHANNEL.get();

        // A full response in the producer queue has earned no delivery credit.
        let (tx, rx) = tokio::sync::mpsc::channel(4);
        tx.send(ChannelEvent::Data(Bytes::from_static(b"ab")))
            .await
            .unwrap();
        tx.send(ChannelEvent::Data(Bytes::from_static(b"cd")))
            .await
            .unwrap();
        tx.send(ChannelEvent::Finished(Ok(()))).await.unwrap();
        let mut body = AccountedBody::new(
            ChannelBody::new(rx, ContentLength::Exact(nonzero!(4))),
            subject(Some(4)),
        );
        assert!(next(&mut body).await.unwrap().is_ok());
        drop(body);
        assert_eq!(metrics::SERVED_CHANNEL.get(), served_before);
        assert_eq!(metrics::BYTES_SERVED_CHANNEL.get(), bytes_before + 2);
        assert!(db_rx.try_recv().is_err());

        // Consuming every promised byte earns precisely one row and credit.
        let (tx, rx) = tokio::sync::mpsc::channel(4);
        tx.send(ChannelEvent::Data(Bytes::from_static(b"abcd")))
            .await
            .unwrap();
        let mut body = AccountedBody::new(
            ChannelBody::new(rx, ContentLength::Exact(nonzero!(4))),
            subject(Some(4)),
        );
        assert!(next(&mut body).await.unwrap().is_ok());
        drop(body);
        assert_eq!(metrics::SERVED_CHANNEL.get(), served_before + 1);
        assert!(matches!(db_rx.try_recv(), Ok(DatabaseCommand::Transfer(cmd)) if cmd.size == 4));
        assert!(db_rx.try_recv().is_err());

        // Unknown-length producer disappearance is cancellation, even after data.
        let (tx, rx) = tokio::sync::mpsc::channel(4);
        tx.send(ChannelEvent::Data(Bytes::from_static(b"abcd")))
            .await
            .unwrap();
        drop(tx);
        let mut body = AccountedBody::new(
            ChannelBody::new(rx, ContentLength::Unknown(nonzero!(100))),
            subject(None),
        );
        assert!(next(&mut body).await.unwrap().is_ok());
        assert!(next(&mut body).await.unwrap().is_err());
        assert!(next(&mut body).await.is_none());
        drop(body);
        assert_eq!(metrics::SERVED_CHANNEL.get(), served_before + 1);
        assert!(db_rx.try_recv().is_err());

        // A later terminal None cannot clear an already observed source failure.
        let (tx, rx) = tokio::sync::mpsc::channel(4);
        tx.send(ChannelEvent::Finished(Err(CacheError::invalid(
            "read cache",
            "failed",
        )
        .into())))
            .await
            .unwrap();
        let mut body = AccountedBody::new(
            ChannelBody::new(rx, ContentLength::Unknown(nonzero!(100))),
            subject(None),
        );
        assert!(next(&mut body).await.unwrap().is_err());
        assert!(next(&mut body).await.is_none());
        drop(body);
        assert_eq!(metrics::SERVED_CHANNEL.get(), served_before + 1);
        assert!(db_rx.try_recv().is_err());
        // Unknown-length success requires the explicit final event to be consumed.
        let (tx, rx) = tokio::sync::mpsc::channel(4);
        tx.send(ChannelEvent::Data(Bytes::from_static(b"ab")))
            .await
            .unwrap();
        tx.send(ChannelEvent::Finished(Ok(()))).await.unwrap();
        let mut body = AccountedBody::new(
            ChannelBody::new(rx, ContentLength::Unknown(nonzero!(100))),
            subject(None),
        );
        assert!(next(&mut body).await.unwrap().is_ok());
        assert!(next(&mut body).await.is_none());
        drop(body);
        assert_eq!(metrics::SERVED_CHANNEL.get(), served_before + 2);
        assert_eq!(metrics::BYTES_SERVED_CHANNEL.get(), bytes_before + 12);
        assert!(matches!(db_rx.try_recv(), Ok(DatabaseCommand::Transfer(cmd)) if cmd.size == 2));
        assert!(db_rx.try_recv().is_err());
    }
    #[test]
    fn passthrough_final_frame_is_clean_completion() {
        use crate::rate_checked_body::ClientBody;
        let inner = ClientBody::new(
            http_body_util::Full::new(Bytes::from_static(b"body")),
            None,
            nonzero!(1),
        );
        let mut body = AccountedBody::new(
            inner,
            Subject::Passthrough {
                host: "passthrough.test".into(),
                path: "/body".into(),
                client: local_client(),
                request_received_at: PreciseInstant::now(),
                request_sent: PreciseInstant::now(),
                relay_slot: passthrough_limiter::admit(None, "/body", &local_client())
                    .expect("uncapped"),
            },
        );
        let before = metrics::SERVED_PASSTHROUGH.get();
        let frame = Pin::new(&mut body)
            .poll_frame(&mut std::task::Context::from_waker(std::task::Waker::noop()));
        assert!(matches!(frame, Poll::Ready(Some(Ok(_)))));
        assert!(body.is_end_stream());
        // Hyper is allowed to stop now, without polling Ready(None).
        drop(body);
        assert_eq!(metrics::SERVED_PASSTHROUGH.get(), before + 1);
    }
}
