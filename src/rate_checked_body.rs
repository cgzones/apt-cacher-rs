use std::{fmt::Debug, num::NonZero};

use bytes::Buf as _;
use coarsetime::{Duration, Instant};
use hyper::body::{Body, Frame, SizeHint};
use log::debug;
use pin_project::pin_project;

use crate::{ClientInfo, HumanFmt, ringbuffer::SumRingBuffer};

/// A rate checker that tracks download speed over a sliding time window.
pub(crate) struct RateChecker {
    buf: SumRingBuffer<usize>,
    last: Instant,
    min_download_rate: NonZero<usize>,
}

/// The result of a failed rate check.
#[derive(Copy, Clone, Debug)]
pub(crate) struct InsufficientRate {
    /// The number of bytes already transferred.
    pub(crate) transferred: usize,
    /// The number of seconds over which the download was measured.
    pub(crate) timeframe: NonZero<usize>,
    /// The minimum download rate required in bytes per second.
    pub(crate) min_rate: NonZero<usize>,
    _private: (),
}

impl InsufficientRate {
    pub(crate) fn display<'a>(&'a self, client: &'a ClientInfo) -> InsufficientRateFormatter<'a> {
        InsufficientRateFormatter { rate: self, client }
    }
}

pub(crate) struct InsufficientRateFormatter<'a> {
    rate: &'a InsufficientRate,
    client: &'a ClientInfo,
}

impl std::fmt::Display for InsufficientRateFormatter<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Timeout occurred for client {} after a download rate of {} [< {}] for the last {} seconds",
            self.client,
            HumanFmt::Rate(
                self.rate.transferred as u64,
                Duration::from_secs(self.rate.timeframe.get() as u64)
            ),
            HumanFmt::Rate(self.rate.min_rate.get() as u64, Duration::from_secs(1)),
            self.rate.timeframe,
        )
    }
}

impl RateChecker {
    /// Creates a new `RateChecker` with the given minimum download rate and timeframe.
    #[must_use]
    pub(crate) fn with_timeframe(
        min_download_rate: NonZero<usize>,
        timeframe: NonZero<usize>,
    ) -> Self {
        Self {
            buf: SumRingBuffer::new(timeframe),
            last: Instant::now(),
            min_download_rate,
        }
    }

    /// Adds the given number of bytes to the rate checker.
    pub(crate) fn add(&mut self, bytes: usize) {
        let elapsed = self.last.elapsed();
        let elapsed_secs = elapsed.as_secs();
        if elapsed_secs >= 1 {
            if elapsed_secs > 1 {
                debug!(
                    "RateChecker: {:.2}s elapsed since last poll receiving {} ({})",
                    elapsed.as_f64(),
                    HumanFmt::Size(bytes as u64),
                    HumanFmt::Rate(bytes as u64, elapsed)
                );
                for _ in 1..elapsed_secs {
                    self.buf.push(0);
                }
            }
            self.buf.push(bytes);
            self.last = self
                .last
                .checked_add(Duration::from_secs(elapsed_secs))
                .expect("Instant should be representable");
        } else {
            self.buf.add_back(bytes);
        }
    }

    /// Checks if the download rate is below the minimum threshold and returns an `InsufficientRate` error if so.
    #[must_use]
    pub(crate) fn check_fail(&self) -> Option<InsufficientRate> {
        if self.buf.is_full() {
            let transferred = self.buf.sum();
            let timeframe = self.buf.capacity();
            if transferred / timeframe < self.min_download_rate.get() {
                Some(InsufficientRate {
                    transferred,
                    timeframe,
                    min_rate: self.min_download_rate,
                    _private: (),
                })
            } else {
                None
            }
        } else {
            None
        }
    }
}

/// Error type for `RateCheckedBody` operations.
pub(crate) enum RateCheckedBodyErr<E> {
    /// The download rate is below the minimum threshold.
    RateTimeout(InsufficientRate),
    /// An error occurred while reading from the inner body.
    Inner(E),
}

/// A `Body` wrapper that checks the download rate against a minimum threshold.
#[pin_project]
pub(crate) struct RateCheckedBody<B>
where
    B: Body,
{
    #[pin]
    inner: B,
    rchecker: RateChecker,
}

impl<B> RateCheckedBody<B>
where
    B: Body,
{
    /// Creates a new `RateCheckedBody` that wraps the given `body` and checks the download rate against the given `min_download_rate` over the given `timeframe`.
    #[must_use]
    pub(crate) fn new(
        body: B,
        min_download_rate: NonZero<usize>,
        timeframe: NonZero<usize>,
    ) -> Self {
        Self {
            inner: body,
            rchecker: RateChecker::with_timeframe(min_download_rate, timeframe),
        }
    }
}

impl<B> Body for RateCheckedBody<B>
where
    B: Body,
{
    type Data = B::Data;
    type Error = Box<RateCheckedBodyErr<B::Error>>;

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn poll_frame(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        if let Some(download_rate_err) = self.rchecker.check_fail() {
            return std::task::Poll::Ready(Some(Err(Box::new(RateCheckedBodyErr::RateTimeout(
                download_rate_err,
            )))));
        }

        let self_mut = self.project();
        let msg = self_mut.inner.poll_frame(cx);

        if let std::task::Poll::Ready(Some(Ok(ref frame))) = msg
            && let Some(data) = frame.data_ref()
        {
            self_mut.rchecker.add(data.remaining());
        }

        msg.map_err(|e| Box::new(RateCheckedBodyErr::Inner(e)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nonzero;

    #[test]
    fn rate_checker_triggers_when_slow() {
        let mut rc = RateChecker::with_timeframe(nonzero!(100), nonzero!(3));

        // Simulate 1 byte per second for 3 seconds.
        // Use 1050ms to ensure coarsetime registers a full second.
        for _ in 0..3 {
            std::thread::sleep(std::time::Duration::from_millis(1050));
            rc.add(1);
        }

        // Buffer should now be full with 3 bytes over 3s = 1 B/s < 100 B/s.
        let fail = rc.check_fail();
        assert!(fail.is_some(), "rate check should fail for slow transfer");
        let ir = fail.unwrap();
        assert!(ir.transferred <= 3);
        assert_eq!(ir.min_rate, nonzero!(100));
    }

    #[test]
    fn rate_checker_passes_when_fast() {
        let mut rc = RateChecker::with_timeframe(nonzero!(100), nonzero!(3));

        // Simulate 500 bytes per second for 3 seconds.
        for _ in 0..3 {
            std::thread::sleep(std::time::Duration::from_millis(1050));
            rc.add(500);
        }

        // ~1500 bytes over 3s = 500 B/s > 100 B/s.
        assert!(
            rc.check_fail().is_none(),
            "rate check should pass for fast transfer"
        );
    }

    #[test]
    fn rate_checker_not_full_yet() {
        let mut rc = RateChecker::with_timeframe(nonzero!(100), nonzero!(3));

        // Only 1 second elapsed — buffer not full.
        std::thread::sleep(std::time::Duration::from_millis(1050));
        rc.add(1);

        assert!(
            rc.check_fail().is_none(),
            "should not fail before buffer is full"
        );
    }

    #[test]
    fn rate_checker_fills_zeros_for_gaps() {
        let mut rc = RateChecker::with_timeframe(nonzero!(100), nonzero!(3));

        // Sleep 4 seconds to ensure at least 3 elapsed seconds are seen by
        // coarsetime (which has ~1ms resolution but rounding can lose a tick).
        std::thread::sleep(std::time::Duration::from_millis(3100));
        rc.add(1);

        // Buffer should be [0, 0, 1] — full with 1 byte over 3s = 0 B/s < 100 B/s.
        let fail = rc.check_fail();
        assert!(fail.is_some(), "rate check should fail after gap");
    }
}
