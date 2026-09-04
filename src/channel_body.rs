use http_body::{Body, Frame, SizeHint};

use crate::{error::MirrorDownloadRate, metrics, upstream_head::ContentLength};

#[derive(Debug)]
pub(crate) enum ChannelBodyError {
    MirrorDownloadRate(MirrorDownloadRate),
    ContentTooLarge {
        announced: ContentLength,
        received: u64,
    },
}

pub(crate) struct ChannelBody {
    receiver: tokio::sync::mpsc::Receiver<Result<bytes::Bytes, MirrorDownloadRate>>,
    content_length: ContentLength,
    received: u64,
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
        receiver: tokio::sync::mpsc::Receiver<Result<bytes::Bytes, MirrorDownloadRate>>,
        content_length: ContentLength,
    ) -> Self {
        Self {
            receiver,
            content_length,
            received: 0,
            channel_closed: false,
            errored: false,
        }
    }

    fn remaining(&self) -> u64 {
        self.content_length.upper().get() - self.received
    }

    /// Only an `Exact` announcement has a total to deliver; `Unknown` is an
    /// upper bound that reaching says nothing about.
    fn announced_total_delivered(&self) -> bool {
        matches!(self.content_length, ContentLength::Exact(total) if self.received == total.get())
    }
}

impl Drop for ChannelBody {
    fn drop(&mut self) {
        // "Fully delivered" (per `metrics.rs` SERVED_TOTAL doc) requires
        // reaching a terminal state AND never having surfaced an error. For
        // `Exact` only delivery of the announced total counts - a sender that
        // drops the channel early (e.g. a cache-read failure abort) closed
        // the channel but truncated the body. For `Upper` (unknown length) a
        // clean channel close is the only terminal signal there is. An
        // upstream error vetoes the credit even when the terminal flag is
        // set. Preserves the parent/subset invariant from `metrics.rs`:
        // `SERVED_TOTAL` = sum of per-path `SERVED_*`.
        let terminal = match self.content_length {
            ContentLength::Exact(_) => self.announced_total_delivered(),
            ContentLength::Unknown(_) => self.channel_closed,
        };
        if terminal && !self.errored {
            metrics::SERVED_CHANNEL.increment();
            metrics::SERVED_TOTAL.increment();
        }
    }
}

impl Body for ChannelBody {
    type Data = bytes::Bytes;
    type Error = Box<ChannelBodyError>;

    fn size_hint(&self) -> SizeHint {
        match self.content_length {
            ContentLength::Exact(_) => SizeHint::with_exact(self.remaining()),
            ContentLength::Unknown(_) => {
                let mut sz = SizeHint::new();
                sz.set_upper(self.remaining());
                sz
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        // Hint per the `Body` trait: `true` implies `poll_frame` will only
        // yield `Ready(None)`. Mirror every terminal short-circuit in
        // `poll_frame` - the announced total delivered, the channel closed,
        // or an error surfaced - so a consumer relying on the hint stops
        // instead of issuing a redundant poll after the body has terminated.
        self.announced_total_delivered() || self.channel_closed || self.errored
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
                    let received = self.received.saturating_add(datalen);
                    if received > self.content_length.upper().get() {
                        metrics::UPSTREAM_PROTOCOL_VIOLATION.increment();
                        self.errored = true;
                        return Err(Box::new(ChannelBodyError::ContentTooLarge {
                            announced: self.content_length,
                            received,
                        }));
                    }
                    self.received = received;
                    metrics::BYTES_SERVED_CHANNEL.increment_by(datalen);
                    Ok(Frame::data(data))
                }
                Err(err) => {
                    self.errored = true;
                    Err(Box::new(ChannelBodyError::MirrorDownloadRate(err)))
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
    use crate::channel_body::ChannelBodyError;

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
            matches!(*err, ChannelBodyError::ContentTooLarge { received: 5, .. }),
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
            matches!(*err, ChannelBodyError::ContentTooLarge { received: 4, .. }),
            "expected ContentTooLarge {{ received: 4, .. }}, got {err:?}"
        );
    }

    /// After a surfaced error `poll_frame` only ever yields `Ready(None)`, so
    /// `is_end_stream()` must report `true` even when neither the announced
    /// total was delivered nor the channel closed - otherwise a consumer using
    /// the hint issues a redundant poll on the terminated body.
    #[tokio::test]
    async fn errored_marks_end_of_stream() {
        let (tx, rx) = tokio::sync::mpsc::channel(4);
        let mut body = ChannelBody::new(rx, ContentLength::Exact(nz(3)));

        // Over-announce within a single frame: sets `errored` while
        // `delivered_announced` and `channel_closed` both stay `false`.
        tx.send(Ok(bytes::Bytes::from_static(b"abcd")))
            .await
            .expect("send");

        let result = std::future::poll_fn(|cx| Pin::new(&mut body).poll_frame(cx))
            .await
            .expect("frame present");
        let err = result.expect_err("expected ContentTooLarge, got Ok frame");
        assert!(matches!(*err, ChannelBodyError::ContentTooLarge { .. }));

        assert!(
            body.is_end_stream(),
            "is_end_stream() must be true once `errored` is set"
        );

        drop(tx);
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
