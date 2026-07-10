use std::num::NonZero;

use bytes::Buf as _;
use http_body::{Body, Frame, SizeHint};
use pin_project::pin_project;

use crate::rate_checker::{InsufficientRate, RateCheckDirection, RateChecker};

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
    direction: RateCheckDirection,
}

impl<B> RateCheckedBody<B>
where
    B: Body,
{
    /// Creates a new `RateCheckedBody` that wraps the given `body` and checks the download rate against the given `min_download_rate` over the given `timeframe`.
    #[must_use]
    fn new(
        body: B,
        min_download_rate: NonZero<usize>,
        timeframe: NonZero<usize>,
        direction: RateCheckDirection,
    ) -> Self {
        Self {
            inner: body,
            rchecker: RateChecker::with_timeframe(min_download_rate, timeframe),
            direction,
        }
    }
}

impl<B> Body for RateCheckedBody<B>
where
    B: Body,
{
    type Data = B::Data;
    type Error = Box<RateCheckedBodyErr<B::Error>>;

    #[inline]
    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }

    #[inline]
    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn poll_frame(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        if let Some(download_rate_err) = self.rchecker.check_fail(self.direction) {
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

/// A `Body` that is optionally wrapped in a [`RateCheckedBody`].
///
/// Lets call sites express "rate-check this body if `min_download_rate` is
/// configured, otherwise pass it through" without manually picking between
/// two body shapes — the unified `Error` (`Box<RateCheckedBodyErr<B::Error>>`)
/// matches the rated case so downstream error mapping is identical.
#[pin_project(project = MaybeRatedProj)]
#[expect(
    clippy::large_enum_variant,
    reason = "RateCheckedBody embeds an inline SumRingBuffer sized for the \
              default rate_check_timeframe (30 entries) so rated requests \
              skip the per-request heap allocation; boxing the variant \
              would re-introduce exactly the alloc we're avoiding"
)]
pub(crate) enum MaybeRated<B>
where
    B: Body,
{
    Plain(#[pin] B),
    Rated(#[pin] RateCheckedBody<B>),
}

impl<B> MaybeRated<B>
where
    B: Body,
{
    #[must_use]
    pub(crate) fn new(
        body: B,
        min_download_rate: Option<NonZero<usize>>,
        timeframe: NonZero<usize>,
        direction: RateCheckDirection,
    ) -> Self {
        match min_download_rate {
            Some(rate) => Self::Rated(RateCheckedBody::new(body, rate, timeframe, direction)),
            None => Self::Plain(body),
        }
    }
}

impl<B> Body for MaybeRated<B>
where
    B: Body,
{
    type Data = B::Data;
    type Error = Box<RateCheckedBodyErr<B::Error>>;

    #[inline]
    fn size_hint(&self) -> SizeHint {
        match self {
            Self::Plain(body) => body.size_hint(),
            Self::Rated(body) => body.size_hint(),
        }
    }

    #[inline]
    fn is_end_stream(&self) -> bool {
        match self {
            Self::Plain(body) => body.is_end_stream(),
            Self::Rated(body) => body.is_end_stream(),
        }
    }

    #[inline]
    fn poll_frame(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        match self.project() {
            MaybeRatedProj::Plain(body) => body
                .poll_frame(cx)
                .map_err(|e| Box::new(RateCheckedBodyErr::Inner(e))),
            MaybeRatedProj::Rated(body) => body.poll_frame(cx),
        }
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
        let fail = rc.check_fail(RateCheckDirection::Client);
        assert!(fail.is_some(), "rate check should fail for slow transfer");
        let ir = fail.unwrap();
        assert_eq!(ir.transferred, 3);
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
            rc.check_fail(RateCheckDirection::Client).is_none(),
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
            rc.check_fail(RateCheckDirection::Client).is_none(),
            "should not fail before buffer is full"
        );
    }

    #[test]
    fn rate_checker_fills_zeros_for_gaps() {
        let mut rc = RateChecker::with_timeframe(nonzero!(100), nonzero!(3));

        // Sleep slightly over 3 seconds to ensure at least 3 elapsed seconds
        // are seen by coarsetime (which has ~1ms resolution but rounding can
        // lose a tick).
        std::thread::sleep(std::time::Duration::from_millis(3100));
        rc.add(1);

        // Buffer should be [0, 0, 1] — full with 1 byte over 3s = 0 B/s < 100 B/s.
        let fail = rc.check_fail(RateCheckDirection::Client);
        assert!(fail.is_some(), "rate check should fail after gap");
    }
}
