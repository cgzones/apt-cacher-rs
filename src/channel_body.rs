use hyper::body::{Body, Frame, SizeHint};

use crate::{ContentLength, ProxyCacheError, error, metrics};

pub(crate) enum ChannelBodyError {
    MirrorDownloadRate(error::MirrorDownloadRate),
}

#[derive(Clone, Copy)]
enum Remaining {
    Exact(u64),
    Upper(u64),
}

impl Remaining {
    fn try_consume(self, n: u64) -> Option<Self> {
        match self {
            Self::Exact(v) => v.checked_sub(n).map(Self::Exact),
            Self::Upper(v) => v.checked_sub(n).map(Self::Upper),
        }
    }

    fn to_size_hint(self) -> SizeHint {
        match self {
            Self::Exact(n) => SizeHint::with_exact(n),
            Self::Upper(n) => {
                let mut sz = SizeHint::new();
                sz.set_upper(n);
                sz
            }
        }
    }
}

pub(crate) struct ChannelBody {
    receiver: tokio::sync::mpsc::Receiver<Result<bytes::Bytes, ChannelBodyError>>,
    content_length: ContentLength,
    remaining: Remaining,
    received: u64,
    complete: bool,
}

impl ChannelBody {
    #[must_use]
    pub(crate) fn new(
        receiver: tokio::sync::mpsc::Receiver<Result<bytes::Bytes, ChannelBodyError>>,
        content_length: ContentLength,
    ) -> Self {
        let remaining = match content_length {
            ContentLength::Exact(size) => Remaining::Exact(size.get()),
            ContentLength::Unknown(size) => Remaining::Upper(size.get()),
        };

        Self {
            receiver,
            content_length,
            remaining,
            received: 0,
            complete: false,
        }
    }
}

impl Drop for ChannelBody {
    fn drop(&mut self) {
        if self.complete {
            metrics::SERVED_CHANNEL.increment();
            metrics::SERVED_TOTAL.increment();
        }
    }
}

impl Body for ChannelBody {
    type Data = bytes::Bytes;
    type Error = Box<ProxyCacheError>;

    fn size_hint(&self) -> hyper::body::SizeHint {
        self.remaining.to_size_hint()
    }

    fn is_end_stream(&self) -> bool {
        self.complete
    }

    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        if self.is_end_stream() {
            return std::task::Poll::Ready(None);
        }

        let msg = self.receiver.poll_recv(cx);
        if matches!(msg, std::task::Poll::Ready(None)) {
            self.complete = true;
        }

        msg.map(|d| {
            d.map(|b| match b {
                Ok(data) => {
                    let datalen = data.len() as u64;
                    match self.remaining.try_consume(datalen) {
                        None => {
                            metrics::UPSTREAM_PROTOCOL_VIOLATION.increment();
                            Err(Box::new(ProxyCacheError::ContentTooLarge {
                                announced: self.content_length,
                                received: self.received + datalen,
                            }))
                        }
                        Some(updated) => {
                            self.received += datalen;
                            self.remaining = updated;
                            // For an exact announced size, reaching `Exact(0)`
                            // means every announced byte has been delivered.
                            // Probe the receiver one more time before flipping
                            // `complete` so a sender that pushes additional
                            // frames *after* the announced total is still
                            // caught as `ContentTooLarge` - without this peek,
                            // `is_end_stream() == true` would short-circuit
                            // the next `poll_frame` and the extra frame would
                            // be silently dropped. `Ready(None)` confirms a
                            // clean close; `Pending` means no extra frame is
                            // queued right now, in which case we still flip
                            // `complete` so the `Drop` accounting fires even
                            // if the body is dropped before observing the
                            // channel close (preserving the parent/subset
                            // invariant: `SERVED_TOTAL` = sum of per-path
                            // `SERVED_*` documented in `metrics.rs`). The
                            // `Upper` (unknown-length) case keeps the
                            // channel-close signal as the only completion
                            // indicator: `Upper(0)` only means the announced
                            // cap has been hit, not that the sender is done.
                            if matches!(updated, Remaining::Exact(0)) {
                                // `Ready(None)` (clean close) and `Pending`
                                // (no extra frame queued) fall through to
                                // setting `complete`. An empty
                                // `Ready(Some(Ok(_)))` frame is a no-op
                                // (no bytes, no violation). `Ready(Some(Err(_)))`
                                // would surface as the body's error on the
                                // next poll, but `complete` is still flipped
                                // here so the Drop-time accounting fires.
                                if let std::task::Poll::Ready(Some(Ok(extra))) =
                                    self.receiver.poll_recv(cx)
                                    && !extra.is_empty()
                                {
                                    metrics::UPSTREAM_PROTOCOL_VIOLATION.increment();
                                    return Err(Box::new(ProxyCacheError::ContentTooLarge {
                                        announced: self.content_length,
                                        received: self.received + extra.len() as u64,
                                    }));
                                }
                                self.complete = true;
                            }
                            metrics::BYTES_SERVED_CHANNEL.increment_by(datalen);
                            Ok(Frame::data(data))
                        }
                    }
                }
                Err(err) => Err(Box::new(err.into())),
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use std::num::NonZero;
    use std::pin::Pin;
    use std::task::Poll;

    use super::{ChannelBody, ContentLength};
    use crate::ProxyCacheError;
    use hyper::body::Body as _;

    fn nz(v: u64) -> NonZero<u64> {
        NonZero::new(v).expect("non-zero")
    }

    /// Send exactly the announced byte count, then drop the sender to close
    /// the channel. The body should complete cleanly.
    #[tokio::test]
    async fn exact_clean_close_completes() {
        let (tx, rx) = tokio::sync::mpsc::channel(4);
        let mut body = ChannelBody::new(rx, ContentLength::Exact(nz(4)));

        tx.send(Ok(bytes::Bytes::from_static(b"abcd")))
            .await
            .expect("send");
        drop(tx);

        let frame = std::future::poll_fn(|cx| Pin::new(&mut body).poll_frame(cx))
            .await
            .expect("frame present")
            .expect("frame ok");
        assert_eq!(frame.into_data().expect("data frame").as_ref(), b"abcd");
        assert!(body.is_end_stream());

        // The next poll must return None.
        let next = std::future::poll_fn(|cx| Pin::new(&mut body).poll_frame(cx)).await;
        assert!(next.is_none());
    }

    /// Sender pushes an additional non-empty frame after the announced
    /// `Exact(N)` total has been delivered. The defence-in-depth check
    /// must surface this as `ContentTooLarge` instead of silently dropping
    /// the extra bytes by short-circuiting on `is_end_stream()`.
    #[tokio::test]
    async fn exact_over_announce_after_total_is_caught() {
        let (tx, rx) = tokio::sync::mpsc::channel(4);
        let mut body = ChannelBody::new(rx, ContentLength::Exact(nz(4)));

        // Queue the announced total *and* a trailing over-announce frame
        // before polling, so the second `poll_recv` inside `poll_frame`
        // sees `Ready(Some(extra))`.
        tx.send(Ok(bytes::Bytes::from_static(b"abcd")))
            .await
            .expect("send");
        tx.send(Ok(bytes::Bytes::from_static(b"X")))
            .await
            .expect("send extra");
        drop(tx);

        let result = std::future::poll_fn(|cx| Pin::new(&mut body).poll_frame(cx))
            .await
            .expect("frame present");
        let err = result.expect_err("expected ContentTooLarge, got Ok frame");
        assert!(
            matches!(*err, ProxyCacheError::ContentTooLarge { received: 5, .. }),
            "expected ContentTooLarge {{ received: 5, .. }}, got {err:?}"
        );
    }

    /// Over-announce within a single frame still routes through the
    /// `try_consume` arm.
    #[tokio::test]
    async fn exact_over_announce_within_frame_is_caught() {
        let (tx, rx) = tokio::sync::mpsc::channel(4);
        let mut body = ChannelBody::new(rx, ContentLength::Exact(nz(3)));

        tx.send(Ok(bytes::Bytes::from_static(b"abcd")))
            .await
            .expect("send");
        drop(tx);

        let result = std::future::poll_fn(|cx| Pin::new(&mut body).poll_frame(cx))
            .await
            .expect("frame present");
        let err = result.expect_err("expected ContentTooLarge, got Ok frame");
        assert!(
            matches!(*err, ProxyCacheError::ContentTooLarge { received: 4, .. }),
            "expected ContentTooLarge {{ received: 4, .. }}, got {err:?}"
        );
    }

    /// When the announced total is reached but the receiver is still
    /// `Pending` (no extra frame queued, no close), `complete` must still
    /// be flipped so the Drop-time metric increment fires - preserving the
    /// parent/subset invariant from the prior fix.
    #[tokio::test]
    async fn exact_pending_after_total_still_marks_complete() {
        let (tx, rx) = tokio::sync::mpsc::channel(4);
        let mut body = ChannelBody::new(rx, ContentLength::Exact(nz(4)));

        tx.send(Ok(bytes::Bytes::from_static(b"abcd")))
            .await
            .expect("send");
        // Deliberately do NOT drop `tx`; the second `poll_recv` inside
        // `poll_frame` should observe `Pending`.

        let waker = futures_util::task::noop_waker();
        let mut cx = std::task::Context::from_waker(&waker);
        let poll = Pin::new(&mut body).poll_frame(&mut cx);
        let Poll::Ready(Some(Ok(frame))) = poll else {
            unreachable!("expected Ready(Some(Ok(_))) for the last announced frame");
        };
        assert_eq!(frame.into_data().expect("data frame").as_ref(), b"abcd");
        assert!(body.is_end_stream(), "complete must be set on Exact(0)");

        // Keep `tx` alive so the test reflects the Pending branch.
        drop(tx);
    }
}
