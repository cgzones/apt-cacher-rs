//! High-resolution monotonic instant for per-request timing.
//!
//! The crate bans `std::time::Instant` (`clippy.toml`) in favour of
//! `coarsetime::Instant`, whose ~1ms resolution is too coarse to measure
//! host-local sub-millisecond transfers - they collapse to a zero-length
//! window and render as `???B/s`. This newtype is the one exception: it
//! wraps the std clock for the handful of *per-request* measurements. Hot
//! per-frame paths stay on `coarsetime::Instant`.
#![expect(
    clippy::disallowed_types,
    reason = "deliberate per-request high-resolution clock; coarsetime's ~1ms resolution cannot measure sub-ms host-local transfers"
)]

use std::time::Duration;

#[derive(Clone, Copy, Debug)]
pub(crate) struct PreciseInstant(std::time::Instant);

impl PreciseInstant {
    #[must_use]
    pub(crate) fn now() -> Self {
        Self(std::time::Instant::now())
    }

    #[must_use]
    pub(crate) fn elapsed(self) -> Duration {
        self.0.elapsed()
    }

    /// Saturates at zero when the window is inverted (matches
    /// `coarsetime::Instant::duration_since`).
    #[must_use]
    pub(crate) fn duration_since(self, earlier: Self) -> Duration {
        self.0.saturating_duration_since(earlier.0)
    }
}
