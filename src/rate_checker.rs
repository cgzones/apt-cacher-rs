use std::num::NonZero;

use coarsetime::{Duration, Instant};
use log::debug;

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
    /// The number of bytes already transferred.
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
        write!(
            f,
            "Timeout occurred{context} after a download rate of {} [< {}] for the last {} seconds",
            HumanFmt::Rate(
                self.transferred as u64,
                Duration::from_secs(self.timeframe.get() as u64)
            ),
            HumanFmt::Rate(self.min_rate.get() as u64, Duration::from_secs(1)),
            self.timeframe,
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
