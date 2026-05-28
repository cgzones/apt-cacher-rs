//! Shared formatting for the per-request rate-logging segments.
//!
//! Every download/serve/passthrough success log builds the trailing
//! parenthesised part of its message from these segments and nothing else,
//! so the format stays identical across the hyper, sendfile and splice
//! backends.

use coarsetime::Duration;

use crate::humanfmt::HumanFmt;

/// `upstream <size> at <rate>` -- body bytes received from the upstream mirror
/// over the upstream-rate window.
#[must_use]
pub(crate) fn upstream_segment(bytes: u64, window: Duration) -> String {
    format!(
        "upstream {} at {}",
        HumanFmt::Size(bytes),
        HumanFmt::Rate(bytes, window)
    )
}

/// `client <size> at <rate>` -- bytes delivered to the client over the
/// client-rate window, for a fully-served response.
#[must_use]
pub(crate) fn client_segment(bytes: u64, window: Duration) -> String {
    format!(
        "client {} at {}",
        HumanFmt::Size(bytes),
        HumanFmt::Rate(bytes, window)
    )
}

/// `client disconnected after <time> (<size>)` -- the client dropped before
/// receiving the whole response; `bytes` is the best-effort count streamed
/// toward it.
#[must_use]
pub(crate) fn client_disconnect_segment(bytes: u64, elapsed: Duration) -> String {
    format!(
        "client disconnected after {} ({})",
        HumanFmt::Time(elapsed.into()),
        HumanFmt::Size(bytes)
    )
}

#[cfg(test)]
mod tests {
    use coarsetime::Duration;

    use super::{client_disconnect_segment, client_segment, upstream_segment};

    #[test]
    fn upstream_segment_format() {
        // `coarsetime::Duration::from_millis` encodes sub-second time at ~0.977ms
        // resolution, so from_millis(50) stores ~48.8ms -- the literals below
        // reflect coarsetime's quantized output, not a mathematically exact 50ms.
        assert_eq!(
            upstream_segment(4_050_000, Duration::from_millis(50)),
            "upstream 4.05MB at 82.9MB/s"
        );
    }

    #[test]
    fn client_segment_format() {
        assert_eq!(
            client_segment(1_000_000, Duration::from_millis(1000)),
            "client 1.00MB at 1.00MB/s"
        );
    }

    #[test]
    fn client_disconnect_segment_format() {
        // `coarsetime::Duration::from_millis` encodes sub-second time at ~0.977ms
        // resolution; 18ms renders as the nearest representable window.
        assert_eq!(
            client_disconnect_segment(1_200_000, Duration::from_millis(18)),
            "client disconnected after 17.6ms (1.20MB)"
        );
    }

    #[test]
    fn upstream_segment_zero_window() {
        assert_eq!(
            upstream_segment(500, Duration::from_millis(0)),
            "upstream 500B at ???B/s"
        );
    }

    #[test]
    fn client_disconnect_segment_zero_bytes() {
        // `coarsetime::Duration::from_millis` encodes sub-second time at ~0.977ms
        // resolution; 5ms renders as the nearest representable window.
        assert_eq!(
            client_disconnect_segment(0, Duration::from_millis(5)),
            "client disconnected after 4.88ms (0B)"
        );
    }
}
