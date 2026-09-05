//! Shared formatting for the per-request rate-logging segments.
//!
//! Every download/serve/passthrough success log builds the trailing
//! parenthesised part of its message from these segments and nothing else,
//! so the format stays identical across the hyper, sendfile and splice
//! backends.

use std::fmt;
use std::time::Duration;

use crate::humanfmt::HumanFmt;

/// A rate-log segment formatted directly into the logger's output buffer.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Segment {
    kind: SegmentKind,
    bytes: u64,
    window: Duration,
}

#[derive(Clone, Copy, Debug)]
enum SegmentKind {
    Upstream,
    Client,
    Disconnected,
}

impl fmt::Display for Segment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self {
            kind,
            bytes,
            window,
        } = *self;
        let label = match kind {
            SegmentKind::Upstream => "upstream",
            SegmentKind::Client => "client",
            SegmentKind::Disconnected => {
                return write!(
                    f,
                    "client disconnected after {} ({})",
                    HumanFmt::Time(window),
                    HumanFmt::Size(bytes),
                );
            }
        };
        write!(
            f,
            "{label} {} at {}",
            HumanFmt::Size(bytes),
            HumanFmt::Rate(bytes, window)
        )
    }
}

/// `upstream <size> at <rate>` -- body bytes received from the upstream mirror
/// over the upstream-rate window.
#[must_use]
pub(crate) fn upstream_segment(bytes: u64, window: Duration) -> Segment {
    Segment {
        kind: SegmentKind::Upstream,
        bytes,
        window,
    }
}

/// `client <size> at <rate>` -- bytes delivered to the client over the
/// client-rate window, for a fully-served response.
#[must_use]
pub(crate) fn client_segment(bytes: u64, window: Duration) -> Segment {
    Segment {
        kind: SegmentKind::Client,
        bytes,
        window,
    }
}

/// `client disconnected after <time> (<size>)` -- the client dropped before
/// receiving the whole response; `bytes` is the best-effort count streamed
/// toward it.
#[must_use]
pub(crate) fn client_disconnect_segment(bytes: u64, elapsed: Duration) -> Segment {
    Segment {
        kind: SegmentKind::Disconnected,
        bytes,
        window: elapsed,
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{client_disconnect_segment, client_segment, upstream_segment};

    #[test]
    fn upstream_segment_format() {
        assert_eq!(
            upstream_segment(4_050_000, Duration::from_millis(50)).to_string(),
            "upstream 4.05MB at 81.0MB/s"
        );
    }

    #[test]
    fn client_segment_format() {
        assert_eq!(
            client_segment(1_000_000, Duration::from_secs(1)).to_string(),
            "client 1.00MB at 1.00MB/s"
        );
    }

    #[test]
    fn client_segment_sub_millisecond_window() {
        // Host-local serves complete in microseconds; the std::time::Instant
        // backing the window has nanosecond resolution, so the rate stays
        // finite instead of collapsing to `???B/s`.
        assert_eq!(
            client_segment(61_700, Duration::from_micros(50)).to_string(),
            "client 61.7kB at 1.23GB/s"
        );
    }

    #[test]
    fn client_disconnect_segment_format() {
        assert_eq!(
            client_disconnect_segment(1_200_000, Duration::from_millis(18)).to_string(),
            "client disconnected after 18.0ms (1.20MB)"
        );
    }

    #[test]
    fn upstream_segment_zero_window() {
        assert_eq!(
            upstream_segment(500, Duration::from_millis(0)).to_string(),
            "upstream 500B at ???B/s"
        );
    }

    #[test]
    fn client_disconnect_segment_zero_bytes() {
        assert_eq!(
            client_disconnect_segment(0, Duration::from_millis(5)).to_string(),
            "client disconnected after 5.00ms (0B)"
        );
    }
}
