use http_body::{Body, Frame, SizeHint};

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
    // For an `Exact` announced length: set when the announced total has been
    // delivered (`Remaining::Exact(0)`). Never set for `Upper` (unknown).
    delivered_announced: bool,
    // Set on the first `Ready(None)` observed from the channel.
    channel_closed: bool,
    // Sticky: set once `poll_frame` has yielded any `Err` (protocol violation
    // or upstream rate error). Vetoes the Drop-time `SERVED_*` credit and
    // short-circuits subsequent polls so the violation counter is not bumped
    // again for the same body.
    errored: bool,
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
            delivered_announced: false,
            channel_closed: false,
            errored: false,
        }
    }
}

impl Drop for ChannelBody {
    fn drop(&mut self) {
        // "Fully delivered" (per `metrics.rs` SERVED_TOTAL doc) requires
        // reaching a terminal state AND never having surfaced an error. For
        // `Exact` the announced total was delivered; for `Upper` the channel
        // closed cleanly. A `ContentTooLarge` after the announced total (or
        // any upstream error) vetoes the credit even when the terminal flag
        // is set. Preserves the parent/subset invariant from `metrics.rs`:
        // `SERVED_TOTAL` = sum of per-path `SERVED_*`.
        if (self.delivered_announced || self.channel_closed) && !self.errored {
            metrics::SERVED_CHANNEL.increment();
            metrics::SERVED_TOTAL.increment();
        }
    }
}

impl Body for ChannelBody {
    type Data = bytes::Bytes;
    type Error = Box<ProxyCacheError>;

    fn size_hint(&self) -> SizeHint {
        self.remaining.to_size_hint()
    }

    fn is_end_stream(&self) -> bool {
        // Hint per the `Body` trait. We return `true` once the announced
        // total has been delivered so well-behaved consumers can stop early;
        // `poll_frame` itself only short-circuits on `channel_closed`, so a
        // consumer that keeps polling still gets `ContentTooLarge` if the
        // upstream pushes more frames after the announced total.
        self.delivered_announced || self.channel_closed
    }

    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        // `errored` short-circuit makes terminal Err idempotent: a consumer
        // that keeps polling after a `ContentTooLarge` does not re-bump
        // `UPSTREAM_PROTOCOL_VIOLATION` per trailing frame.
        if self.channel_closed || self.errored {
            return std::task::Poll::Ready(None);
        }

        let msg = self.receiver.poll_recv(cx);
        if matches!(msg, std::task::Poll::Ready(None)) {
            self.channel_closed = true;
        }

        msg.map(|d| {
            d.map(|b| match b {
                Ok(data) => {
                    let datalen = data.len() as u64;
                    // Any non-empty frame received after the announced total
                    // has been delivered is a protocol violation. Empty frames
                    // are tolerated as a no-op (they consume nothing).
                    if self.delivered_announced && datalen > 0 {
                        metrics::UPSTREAM_PROTOCOL_VIOLATION.increment();
                        self.errored = true;
                        return Err(Box::new(ProxyCacheError::ContentTooLarge {
                            announced: self.content_length,
                            received: self.received + datalen,
                        }));
                    }
                    match self.remaining.try_consume(datalen) {
                        None => {
                            metrics::UPSTREAM_PROTOCOL_VIOLATION.increment();
                            self.errored = true;
                            Err(Box::new(ProxyCacheError::ContentTooLarge {
                                announced: self.content_length,
                                received: self.received + datalen,
                            }))
                        }
                        Some(updated) => {
                            self.received += datalen;
                            self.remaining = updated;
                            if matches!(updated, Remaining::Exact(0)) {
                                self.delivered_announced = true;
                            }
                            metrics::BYTES_SERVED_CHANNEL.increment_by(datalen);
                            Ok(Frame::data(data))
                        }
                    }
                }
                Err(err) => {
                    self.errored = true;
                    Err(Box::new(err.into()))
                }
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use std::num::NonZero;
    use std::pin::Pin;
    use std::task::Poll;

    use http_body::Body as _;

    use super::{ChannelBody, ContentLength};
    use crate::ProxyCacheError;

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
    /// must surface this as `ContentTooLarge` on the next poll instead of
    /// silently dropping the extra bytes.
    #[tokio::test]
    async fn exact_over_announce_after_total_is_caught() {
        let (tx, rx) = tokio::sync::mpsc::channel(4);
        let mut body = ChannelBody::new(rx, ContentLength::Exact(nz(4)));

        tx.send(Ok(bytes::Bytes::from_static(b"abcd")))
            .await
            .expect("send");
        tx.send(Ok(bytes::Bytes::from_static(b"X")))
            .await
            .expect("send extra");
        drop(tx);

        // First poll delivers the announced total.
        let frame = std::future::poll_fn(|cx| Pin::new(&mut body).poll_frame(cx))
            .await
            .expect("frame present")
            .expect("frame ok");
        assert_eq!(frame.into_data().expect("data frame").as_ref(), b"abcd");

        // Second poll surfaces the trailing over-announce frame.
        let result = std::future::poll_fn(|cx| Pin::new(&mut body).poll_frame(cx))
            .await
            .expect("frame present");
        let err = result.expect_err("expected ContentTooLarge, got Ok frame");
        assert!(
            matches!(*err, ProxyCacheError::ContentTooLarge { received: 5, .. }),
            "expected ContentTooLarge {{ received: 5, .. }}, got {err:?}"
        );

        // Further polls must be idempotent (`Ready(None)`) so the violation
        // counter is not bumped again per trailing frame.
        let next = std::future::poll_fn(|cx| Pin::new(&mut body).poll_frame(cx)).await;
        assert!(next.is_none(), "expected Ready(None) after ContentTooLarge");
        let next = std::future::poll_fn(|cx| Pin::new(&mut body).poll_frame(cx)).await;
        assert!(next.is_none(), "expected Ready(None) on subsequent polls");
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

    /// When the announced total is reached but the channel has not yet
    /// closed, `delivered_announced` must be set so `is_end_stream()`
    /// returns `true` and the Drop-time metric increment fires -
    /// preserving the parent/subset invariant.
    #[tokio::test]
    async fn exact_pending_after_total_marks_end_of_stream() {
        let (tx, rx) = tokio::sync::mpsc::channel(4);
        let mut body = ChannelBody::new(rx, ContentLength::Exact(nz(4)));

        tx.send(Ok(bytes::Bytes::from_static(b"abcd")))
            .await
            .expect("send");
        // Deliberately do NOT drop `tx` before polling.

        let waker = futures_util::task::noop_waker();
        let mut cx = std::task::Context::from_waker(&waker);
        let poll = Pin::new(&mut body).poll_frame(&mut cx);
        let Poll::Ready(Some(Ok(frame))) = poll else {
            unreachable!("expected Ready(Some(Ok(_))) for the last announced frame");
        };
        assert_eq!(frame.into_data().expect("data frame").as_ref(), b"abcd");
        assert!(
            body.is_end_stream(),
            "delivered_announced must be set on Exact(0)"
        );

        drop(tx);
    }
}
