use std::num::NonZero;

use coarsetime::{Duration, Instant};
use tracing::debug;

#[cfg(feature = "sendfile")]
use crate::config::Config;
use crate::{humanfmt::HumanFmt, metrics, ringbuffer::SumRingBuffer};

/// A rate checker that tracks download speed over a sliding time window.
pub(crate) struct RateChecker {
    buf: SumRingBuffer<usize>,
    last: Instant,
    min_download_rate: NonZero<usize>,
}

/// The result of a failed rate check.
#[derive(Copy, Clone, Debug)]
pub(crate) struct InsufficientRate {
    /// The number of bytes transferred within the measured timeframe window.
    pub(crate) transferred: usize,
    /// The number of seconds over which the download was measured.
    pub(crate) timeframe: NonZero<usize>,
    /// The minimum download rate required in bytes per second.
    pub(crate) min_rate: NonZero<usize>,
    _private: (),
}

impl InsufficientRate {
    /// Format the rate-timeout message with a required context fragment
    /// inserted after `"Timeout occurred"` (e.g. `" for client foo"`).
    pub(crate) fn fmt_with_context(
        &self,
        f: &mut std::fmt::Formatter<'_>,
        context: std::fmt::Arguments<'_>,
    ) -> std::fmt::Result {
        // Sync point: the prefix "Timeout occurred" plus `{context}` forms the
        // test needle "Timeout occurred for client"; keep that prefix (and the
        // `{context}` insertion point) stable.  The tail is free to change.
        let timeframe = std::time::Duration::from_secs(self.timeframe.get() as u64);
        write!(
            f,
            "Timeout occurred{context} after a download rate of {} (below {}) for the last {}",
            HumanFmt::Rate(self.transferred as u64, timeframe),
            HumanFmt::Rate(
                self.min_rate.get() as u64,
                std::time::Duration::from_secs(1)
            ),
            HumanFmt::Time(timeframe),
        )
    }

    /// Build a `TimedOut` `io::Error` whose message describes the rate
    /// breach in the supplied context (e.g. `" for upstream"`).
    #[cfg(feature = "sendfile")]
    #[must_use]
    pub(crate) fn to_timeout_io_error(self, context: std::fmt::Arguments<'_>) -> std::io::Error {
        struct Adapter<'a, 'b>(&'a InsufficientRate, std::fmt::Arguments<'b>);
        impl std::fmt::Display for Adapter<'_, '_> {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                self.0.fmt_with_context(f, self.1)
            }
        }
        std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            Adapter(&self, context).to_string(),
        )
    }
}

impl RateChecker {
    /// The rate checker `config` asks for, or `None` when `min_download_rate`
    /// is disabled.  The one place the two config keys are paired, so every
    /// rate-checked loop agrees on the averaging window.
    #[cfg(feature = "sendfile")]
    #[must_use]
    pub(crate) fn from_config(config: &Config) -> Option<Self> {
        config
            .min_download_rate
            .map(|rate| Self::with_timeframe(rate, config.rate_check_timeframe))
    }

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

    /// Returns the configured timeframe (in seconds) over which the
    /// rate is averaged.  Used by callers (e.g. `wait_socket_rated`)
    /// that need to size their own poll cadence relative to the window.
    #[cfg(feature = "sendfile")]
    #[must_use]
    pub(crate) fn timeframe(&self) -> NonZero<usize> {
        self.buf.capacity()
    }

    /// Adds the given number of bytes to the rate checker.
    pub(crate) fn add(&mut self, bytes: usize) {
        let elapsed = self.last.elapsed();
        let elapsed_secs = elapsed.as_secs();
        if elapsed_secs >= 1 {
            if elapsed_secs > 1 {
                debug!(
                    "Rate sampling gap of {:.2}s receiving {} ({}); padding the missed seconds with zeros",
                    elapsed.as_f64(),
                    HumanFmt::Size(bytes as u64),
                    HumanFmt::Rate(bytes as u64, elapsed.into())
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
    pub(crate) fn check_fail(&self, direction: RateCheckDirection) -> Option<InsufficientRate> {
        if !self.buf.is_full() {
            return None;
        }

        let transferred = self.buf.sum();
        let timeframe = self.buf.capacity();
        if transferred / timeframe >= self.min_download_rate.get() {
            return None;
        }

        match direction {
            RateCheckDirection::Upstream => metrics::RATE_LIMIT_UPSTREAM.increment(),
            RateCheckDirection::Client => metrics::RATE_LIMIT_CLIENT.increment(),
        }
        Some(InsufficientRate {
            transferred,
            timeframe,
            min_rate: self.min_download_rate,
            _private: (),
        })
    }
}

/// Which side of the proxy a `RateCheckedBody` is measuring.
#[derive(Copy, Clone)]
pub(crate) enum RateCheckDirection {
    Upstream,
    Client,
}

#[cfg(test)]
mod tests {
    use super::{RateCheckDirection, RateChecker};
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

    /// The window is "full" as soon as it holds `timeframe` samples, and the
    /// sub-second path folds into the newest sample rather than pushing a
    /// second one - so a one-second window is armed by the first `add`.
    #[test]
    fn one_second_window_is_armed_by_the_first_sample() {
        let mut rc = RateChecker::with_timeframe(nonzero!(1000), nonzero!(1));
        assert!(
            rc.check_fail(RateCheckDirection::Client).is_none(),
            "an empty window cannot judge a rate"
        );

        rc.add(1);
        let fail = rc
            .check_fail(RateCheckDirection::Client)
            .expect("1 B/s is below the 1000 B/s minimum");
        assert_eq!(fail.transferred, 1);
        assert_eq!(fail.timeframe, nonzero!(1));

        rc.add(5000);
        assert!(
            rc.check_fail(RateCheckDirection::Client).is_none(),
            "the second sample folds into the same window and clears the breach"
        );
    }
}
