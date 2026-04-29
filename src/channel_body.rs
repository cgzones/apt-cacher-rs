use hyper::body::{Body, Frame, SizeHint};

use crate::{ContentLength, ProxyCacheError, error, metrics};

pub(crate) enum ChannelBodyError {
    MirrorDownloadRate(error::MirrorDownloadRate),
}

pub(crate) struct ChannelBody {
    receiver: tokio::sync::mpsc::Receiver<Result<bytes::Bytes, ChannelBodyError>>,
    content_length: ContentLength,
    remaining: SizeHint,
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
            ContentLength::Exact(size) => SizeHint::with_exact(size.get()),
            ContentLength::Unknown(size) => {
                let mut sz = SizeHint::new();
                sz.set_upper(size.get());
                sz
            }
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

impl Body for ChannelBody {
    type Data = bytes::Bytes;
    type Error = Box<ProxyCacheError>;

    fn size_hint(&self) -> hyper::body::SizeHint {
        // TODO: derive Copy for hyper::body::SizeHint
        // https://github.com/hyperium/http-body/pull/164
        self.remaining.clone()
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

                    match (self.remaining.exact(), self.remaining.upper()) {
                        (Some(size), _) => match size.overflowing_sub(datalen) {
                            (_, true) => {
                                metrics::UPSTREAM_PROTOCOL_VIOLATION.increment();
                                Err(Box::new(ProxyCacheError::ContentTooLarge {
                                    announced: self.content_length,
                                    received: self.received + datalen,
                                }))
                            }
                            (val, false) => {
                                self.received += datalen;
                                self.remaining.set_exact(val);
                                metrics::BYTES_SERVED_CHANNEL.increment_by(datalen);
                                Ok(Frame::data(data))
                            }
                        },
                        (None, Some(size)) => match size.overflowing_sub(datalen) {
                            (_, true) => {
                                metrics::UPSTREAM_PROTOCOL_VIOLATION.increment();
                                Err(Box::new(ProxyCacheError::ContentTooLarge {
                                    announced: self.content_length,
                                    received: self.received + datalen,
                                }))
                            }
                            (val, false) => {
                                self.received += datalen;
                                self.remaining.set_upper(val);
                                metrics::BYTES_SERVED_CHANNEL.increment_by(datalen);
                                Ok(Frame::data(data))
                            }
                        },
                        (None, None) => {
                            unreachable!("size hint is either exact or has an upper limit");
                        }
                    }
                }
                Err(err) => Err(Box::new(err.into())),
            })
        })
    }
}
