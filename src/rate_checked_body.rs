use std::{fmt::Debug, num::NonZero, pin::Pin};

use coarsetime::{Duration, Instant};
use hyper::body::{Body, Frame, SizeHint};
use log::debug;

use crate::{HumanFmt, ProxyCacheError, nonzero, ringbuffer::SumRingBuffer};

#[derive(Debug)]
pub(crate) struct RateChecker {
    buf: SumRingBuffer<usize>,
    last: Instant,
    min_download_rate: NonZero<usize>,
}

impl RateChecker {
    const RATE_CHECK_TIME_SLOTS: NonZero<usize> = nonzero!(30); /* 30 seconds */

    #[must_use]
    pub(crate) fn new(min_download_rate: NonZero<usize>) -> Self {
        Self {
            buf: SumRingBuffer::new(Self::RATE_CHECK_TIME_SLOTS),
            last: Instant::now(),
            min_download_rate,
        }
    }

    pub(crate) fn add(&mut self, len: usize) {
        let elapsed = self.last.elapsed();
        let elapsed_secs = elapsed.as_secs();
        if elapsed_secs >= 1 {
            if elapsed_secs > 1 {
                debug!(
                    "RateChecker: more than 1 second ({:.2}s) elapsed since last poll receiving {} ({})",
                    elapsed.as_f64(),
                    HumanFmt::Size(len as u64),
                    HumanFmt::Rate(len as u64, elapsed)
                );
                for _ in 1..elapsed_secs {
                    self.buf.push(0);
                }
            }
            self.buf.push(len);
            self.last = self
                .last
                .checked_add(Duration::from_secs(elapsed_secs))
                .expect("Instant should be representable");
        } else {
            self.buf.add_back(len);
        }
    }

    #[must_use]
    pub(crate) fn check_fail(&self) -> Option<DownloadRateError> {
        if self.buf.is_full() {
            let total = self.buf.sum();
            if total / Self::RATE_CHECK_TIME_SLOTS < self.min_download_rate.get() {
                Some(DownloadRateError {
                    download_size: total,
                    timeframe: self.buf.capacity(),
                })
            } else {
                None
            }
        } else {
            None
        }
    }
}

#[derive(Copy, Clone, Debug)]
pub(crate) struct DownloadRateError {
    pub(crate) download_size: usize,
    pub(crate) timeframe: NonZero<usize>,
}

pub(crate) enum RateCheckedBodyErr {
    DownloadRate(DownloadRateError),
    Hyper(hyper::Error),
    ProxyCache(ProxyCacheError),
}

pub(crate) trait DebugBody: Body + Debug {}

impl<B: Body + Debug, E, F: FnMut(<B as hyper::body::Body>::Error) -> E> DebugBody
    for http_body_util::combinators::MapErr<B, F>
{
}

#[derive(Debug)]
pub(crate) struct RateCheckedBody<D> {
    inner: Pin<Box<dyn DebugBody<Data = D, Error = RateCheckedBodyErr> + Send + Sync + 'static>>,
    rchecker: RateChecker,
}

impl<D: bytes::Buf> RateCheckedBody<D> {
    #[must_use]
    pub(crate) fn new<B>(body: B, min_download_rate: NonZero<usize>) -> Self
    where
        B: DebugBody<Data = D, Error = RateCheckedBodyErr> + Send + Sync + 'static,
        D: bytes::Buf,
    {
        Self {
            inner: Box::pin(body),
            rchecker: RateChecker::new(min_download_rate),
        }
    }
}

impl<D: bytes::Buf> Body for RateCheckedBody<D> {
    type Data = D;
    type Error = RateCheckedBodyErr;

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        if let Some(download_rate_err) = self.rchecker.check_fail() {
            return std::task::Poll::Ready(Some(Err(RateCheckedBodyErr::DownloadRate(
                download_rate_err,
            ))));
        }

        let msg = self.inner.as_mut().poll_frame(cx);
        if let std::task::Poll::Ready(Some(Ok(ref frame))) = msg
            && let Some(data) = frame.data_ref()
        {
            self.rchecker.add(data.remaining());
        }

        msg
    }
}
