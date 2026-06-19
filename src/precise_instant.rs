//! High-resolution monotonic instant for per-request timing.
//!
//! The crate bans `std::time::Instant` (`clippy.toml`) in favour of
//! `coarsetime::Instant`, whose ~1ms resolution is too coarse to measure
//! host-local sub-millisecond transfers - they collapse to a zero-length
//! window and render as `???B/s`. This newtype is the single blessed
//! exception: it wraps the std clock for the handful of *per-request*
//! measurements (request lifetime, client- and upstream-rate windows), each
//! read only twice per request, where ns resolution matters and the ~15ns
//! extra read cost is irrelevant. Hot per-frame paths (`rate_checker`,
//! pool/kTLS GC) stay on `coarsetime::Instant`. The module-level `expect`
//! below is that single, contained exception.
#![expect(
    clippy::disallowed_types,
    reason = "deliberate per-request high-resolution clock; coarsetime's ~1ms resolution cannot measure sub-ms host-local transfers"
)]

use std::time::Duration;

/// Monotonic instant backed by `std::time::Instant` (`CLOCK_MONOTONIC`, ns
/// resolution). See the module docs for why this exists.
#[derive(Clone, Copy, Debug)]
pub(crate) struct PreciseInstant(std::time::Instant);

impl PreciseInstant {
    /// Captures the current time as a `PreciseInstant` using `std::time::Instant::now()`.
    #[must_use]
    pub(crate) fn now() -> Self {
        Self(std::time::Instant::now())
    }

    /// Time elapsed since this instant was captured.
    #[must_use]
    pub(crate) fn elapsed(self) -> Duration {
        self.0.elapsed()
    }

    /// Duration from `earlier` to `self`, saturating at zero when the window
    /// is inverted (matches `coarsetime::Instant::duration_since`).
    #[must_use]
    pub(crate) fn duration_since(self, earlier: Self) -> Duration {
        self.0.saturating_duration_since(earlier.0)
    }
}
