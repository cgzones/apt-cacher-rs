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
