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
    /// Sticky: set once the rate breach has been surfaced. Both consumers
    /// (hyper's `download_file`, the client-facing `ProxyCacheBody`) drop the
    /// body at that error, so this only guards a consumer that polls on -
    /// keeping the terminal `Err` from re-bumping `RATE_LIMIT_*` per poll,
    /// the same idempotency `channel_body`'s `errored` flag provides.
    rate_failed: bool,
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
            rate_failed: false,
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
        // Mirrors the `poll_frame` short-circuit below, per the `Body`
        // contract that `true` implies only `Ready(None)` follows.
        self.rate_failed || self.inner.is_end_stream()
    }

    fn poll_frame(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let self_mut = self.project();
        if *self_mut.rate_failed {
            return std::task::Poll::Ready(None);
        }
        if let Some(download_rate_err) = self_mut.rchecker.check_fail(*self_mut.direction) {
            *self_mut.rate_failed = true;
            return std::task::Poll::Ready(Some(Err(Box::new(RateCheckedBodyErr::RateTimeout(
                download_rate_err,
            )))));
        }

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
    use std::pin::Pin;
    use std::task::{Context, Poll};

    use http_body_util::Full;

    use super::*;
    use crate::nonzero;

    /// A body whose one-second rate window is already full and below the
    /// threshold, so the very next poll must fail the rate check.
    fn breaching_body() -> RateCheckedBody<Full<bytes::Bytes>> {
        let mut body = RateCheckedBody::new(
            Full::new(bytes::Bytes::from_static(b"payload")),
            nonzero!(1000),
            nonzero!(1),
            RateCheckDirection::Client,
        );
        // A single sample fills the one-second window: 1 B/s, far below the
        // 1000 B/s minimum.
        body.rchecker.add(1);
        body
    }

    /// A rate breach is surfaced exactly once. Every later poll yields the
    /// terminal `Ready(None)`, so a consumer that keeps polling cannot
    /// re-bump `RATE_LIMIT_*` per frame - the idempotency `channel_body`'s
    /// `errored` flag provides for its own terminal error.
    #[test]
    fn rate_failure_is_surfaced_once_and_latches() {
        let mut body = breaching_body();
        assert!(!body.is_end_stream());

        let waker = std::task::Waker::noop();
        let mut cx = Context::from_waker(waker);

        let breached = match Pin::new(&mut body).poll_frame(&mut cx) {
            Poll::Ready(Some(Err(err))) => {
                matches!(*err, RateCheckedBodyErr::RateTimeout(_))
            }
            Poll::Ready(Some(Ok(_)) | None) | Poll::Pending => false,
        };
        assert!(breached, "the first poll must surface the rate breach");
        assert!(
            body.is_end_stream(),
            "is_end_stream() must report the latched failure"
        );
        assert!(
            matches!(Pin::new(&mut body).poll_frame(&mut cx), Poll::Ready(None)),
            "a latched rate failure ends the body"
        );
    }

    /// Without a configured minimum rate the wrapper is a pass-through: the
    /// inner body's frames arrive unchanged, only re-boxed into the common
    /// error type.
    #[test]
    fn unrated_body_passes_frames_through() {
        let mut body = MaybeRated::new(
            Full::new(bytes::Bytes::from_static(b"payload")),
            None,
            nonzero!(1),
            RateCheckDirection::Client,
        );
        assert!(matches!(body, MaybeRated::Plain(_)));

        let waker = std::task::Waker::noop();
        let mut cx = Context::from_waker(waker);

        let polled = Pin::new(&mut body).poll_frame(&mut cx);
        let data = match polled {
            Poll::Ready(Some(Ok(frame))) => frame.into_data().ok(),
            Poll::Ready(Some(Err(_)) | None) | Poll::Pending => None,
        };
        assert_eq!(
            data.expect("an unrated body yields its inner data frame"),
            bytes::Bytes::from_static(b"payload"),
        );
    }
}
