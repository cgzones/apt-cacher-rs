//! Growing-file response transport. The feeder sends explicit completion;
//! disappearing producers are cancellation, never an invented clean EOF.
//! All delivery accounting belongs to the outer `AccountedBody`.

use std::{
    pin::Pin,
    task::{Context, Poll},
};

use bytes::Bytes;
use http_body::{Body, Frame, SizeHint};

use crate::{
    transfer_error::{CacheError, DeliveryFailure},
    upstream_head::ContentLength,
};

pub(crate) enum ChannelEvent {
    Data(Bytes),
    Finished(Result<(), DeliveryFailure>),
}

pub(crate) struct ChannelBody {
    receiver: tokio::sync::mpsc::Receiver<ChannelEvent>,
    content_length: ContentLength,
    received: u64,
    terminal: bool,
}

impl ChannelBody {
    #[must_use]
    pub(crate) fn new(
        receiver: tokio::sync::mpsc::Receiver<ChannelEvent>,
        content_length: ContentLength,
    ) -> Self {
        Self {
            receiver,
            content_length,
            received: 0,
            terminal: false,
        }
    }

    fn remaining(&self) -> u64 {
        self.content_length
            .upper()
            .get()
            .saturating_sub(self.received)
    }

    fn announced_total_delivered(&self) -> bool {
        matches!(self.content_length, ContentLength::Exact(total) if self.received == total.get())
    }
}

impl Body for ChannelBody {
    type Data = Bytes;
    type Error = DeliveryFailure;

    fn size_hint(&self) -> SizeHint {
        match self.content_length {
            ContentLength::Exact(_) => SizeHint::with_exact(self.remaining()),
            ContentLength::Unknown(_) => {
                let mut size = SizeHint::new();
                size.set_upper(self.remaining());
                size
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        self.terminal || self.announced_total_delivered()
    }

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        // Exact-length bodies end at their promised byte count, as Hyper
        // does. No later poll can contradict the end-stream hint.
        if self.is_end_stream() {
            return Poll::Ready(None);
        }
        match self.receiver.poll_recv(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Some(ChannelEvent::Data(data))) => {
                let received = self.received.saturating_add(data.len() as u64);
                if received > self.content_length.upper().get() {
                    self.terminal = true;
                    return Poll::Ready(Some(Err(CacheError::invalid(
                        "read growing cache file",
                        format!(
                            "body exceeded promised limit (received {received}, limit {})",
                            self.content_length.upper()
                        ),
                    )
                    .into())));
                }
                self.received = received;
                Poll::Ready(Some(Ok(Frame::data(data))))
            }
            Poll::Ready(Some(ChannelEvent::Finished(result))) => {
                self.terminal = true;
                let result = result.and_then(|()| {
                    if matches!(self.content_length, ContentLength::Exact(_))
                        && !self.announced_total_delivered()
                    {
                        Err(CacheError::invalid(
                            "read growing cache file",
                            format!(
                                "file shorter than promised (received {}, expected {})",
                                self.received,
                                self.content_length.upper()
                            ),
                        )
                        .into())
                    } else {
                        Ok(())
                    }
                });
                Poll::Ready(result.err().map(Err))
            }
            Poll::Ready(None) => {
                self.terminal = true;
                Poll::Ready(Some(Err(DeliveryFailure::Cancelled)))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nonzero;

    async fn next(body: &mut ChannelBody) -> Option<Result<Frame<Bytes>, DeliveryFailure>> {
        std::future::poll_fn(|cx| Pin::new(&mut *body).poll_frame(cx)).await
    }

    #[tokio::test]
    async fn unknown_length_requires_explicit_completion() {
        let (tx, rx) = tokio::sync::mpsc::channel(4);
        let mut body = ChannelBody::new(rx, ContentLength::Unknown(nonzero!(100)));
        tx.send(ChannelEvent::Data(Bytes::from_static(b"abcd")))
            .await
            .unwrap();
        drop(tx);
        assert!(next(&mut body).await.unwrap().is_ok());
        assert!(matches!(
            next(&mut body).await,
            Some(Err(DeliveryFailure::Cancelled))
        ));
        assert!(body.is_end_stream());
        assert!(next(&mut body).await.is_none());
    }

    #[tokio::test]
    async fn explicit_unknown_completion_is_clean() {
        let (tx, rx) = tokio::sync::mpsc::channel(4);
        let mut body = ChannelBody::new(rx, ContentLength::Unknown(nonzero!(100)));
        tx.send(ChannelEvent::Data(Bytes::from_static(b"abcd")))
            .await
            .unwrap();
        tx.send(ChannelEvent::Finished(Ok(()))).await.unwrap();
        assert!(next(&mut body).await.unwrap().is_ok());
        assert!(!body.is_end_stream());
        assert!(next(&mut body).await.is_none());
        assert!(body.is_end_stream());
    }

    #[tokio::test]
    async fn exact_total_is_terminal_even_with_live_sender() {
        let (tx, rx) = tokio::sync::mpsc::channel(4);
        let mut body = ChannelBody::new(rx, ContentLength::Exact(nonzero!(4)));
        tx.send(ChannelEvent::Data(Bytes::from_static(b"abcd")))
            .await
            .unwrap();
        assert!(next(&mut body).await.unwrap().is_ok());
        assert!(body.is_end_stream());
        assert!(next(&mut body).await.is_none());
    }

    #[tokio::test]
    async fn overflow_is_sticky_and_does_not_credit_bytes() {
        let (tx, rx) = tokio::sync::mpsc::channel(4);
        let mut body = ChannelBody::new(rx, ContentLength::Exact(nonzero!(3)));
        tx.send(ChannelEvent::Data(Bytes::from_static(b"abcd")))
            .await
            .unwrap();
        assert!(matches!(
            next(&mut body).await,
            Some(Err(DeliveryFailure::Cache(_)))
        ));
        assert_eq!(body.received, 0);
        assert!(body.is_end_stream());
        assert!(next(&mut body).await.is_none());
    }

    #[tokio::test]
    async fn writer_failure_retains_typed_cause() {
        let (tx, rx) = tokio::sync::mpsc::channel(4);
        let mut body = ChannelBody::new(rx, ContentLength::Unknown(nonzero!(100)));
        tx.send(ChannelEvent::Finished(Err(CacheError::invalid(
            "flush cache file",
            "disk failed",
        )
        .into())))
            .await
            .unwrap();
        assert!(matches!(
            next(&mut body).await,
            Some(Err(DeliveryFailure::Cache(_)))
        ));
        assert!(body.is_end_stream());
        assert!(next(&mut body).await.is_none());
    }

    #[tokio::test]
    async fn explicit_short_completion_is_cache_failure() {
        let (tx, rx) = tokio::sync::mpsc::channel(4);
        let mut body = ChannelBody::new(rx, ContentLength::Exact(nonzero!(4)));
        tx.send(ChannelEvent::Finished(Ok(()))).await.unwrap();
        assert!(matches!(
            next(&mut body).await,
            Some(Err(DeliveryFailure::Cache(_)))
        ));
    }
}
