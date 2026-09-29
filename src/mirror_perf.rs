//! Per-mirror upstream latency and throughput since process start, for the
//! dashboard's Mirrors table: which mirror is slow to answer, and which one
//! delivers too slowly, so the operator can switch to a better one.
//!
//! **Time to first byte** runs from the start of the upstream attempt that
//! answered -- its TCP and TLS connect included when no pooled connection
//! was reused -- to its parsed response head. Earlier failed attempts and
//! the backoff sleeps between them are not part of it; a followed redirect
//! or a resume-anomaly refetch is measured on the last exchange. Recorded
//! for cached-route fetches the upstream answered with a body or a 304,
//! at each fetching backend's upstream-head site (hyper's
//! `serve_new_file_worker`, splice's `splice_proxy_drive`), the same point
//! the request earns its `Origin` row. Not recorded: passthroughs, failed
//! exchanges, other statuses, cleanup's synthetic fetches. One divergence:
//! splice's Auto-mode HTTPS-to-HTTP fallback happens inside one attempt
//! (`connect_upstream`), so while a host's scheme is undecided its first
//! splice sample includes the failed handshake; hyper retries it as a
//! separate attempt.
//!
//! **Throughput** is the wire body bytes of one download (a resumed prefix
//! excluded) over the span from the parsed head to the last body byte,
//! recorded for committed downloads of at least [`MIN_THROUGHPUT_BYTES`]:
//! hyper's `download_file` and splice's commit tail, after the commit. A
//! lower bound while a client is attached: splice paces its upstream reads
//! to the client until demotion, and hyper's figure includes its buffered
//! cache writes.
//!
//! The peak throughput is also splice's demotion-floor reference
//! ([`peak_throughput`], read by `splice/body.rs`'s `DemotionFloor`): what
//! the mirror has shown it can deliver, independent of the transfer a slow
//! client paces. Only the peak serves there, never the latest sample: a
//! slow client's own paced download records a low latest figure, while no
//! download can lower the peak.
//!
//! Stored in a [`MirrorRegistry`] keyed by the canonical mirror: one short
//! lock per answered fetch, no allocation after a mirror's first sighting.

use std::time::Duration;

use hashbrown::HashMap;

use crate::{
    deb_mirror::Mirror,
    mirror_registry::{MAX_MIRRORS, MirrorRegistry, Twin},
    precise_instant::PreciseInstant,
};

/// Downloads smaller than this record no throughput: their span is mostly
/// round trips, not bandwidth.
pub(crate) const MIN_THROUGHPUT_BYTES: u64 = 1024 * 1024;

/// When the attempt that answered started and when its response head was
/// parsed: the two ends of the time to first byte.
#[derive(Clone, Copy, Debug)]
pub(crate) struct HeadTiming {
    pub(crate) attempt_started: PreciseInstant,
    pub(crate) head_at: PreciseInstant,
}

impl HeadTiming {
    #[must_use]
    pub(crate) fn ttfb(self) -> Duration {
        let Self {
            attempt_started,
            head_at,
        } = self;
        head_at.duration_since(attempt_started)
    }
}

/// A latest sample and when it was taken, so twins merge to the newer one.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Latest<T> {
    pub(crate) value: T,
    /// Coarse monotonic ticks of the sample.
    at: u64,
}

/// One mirror's latency and throughput since process start.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct MirrorPerf {
    pub(crate) ttfb: Option<Latest<Duration>>,
    /// The longest time to first byte.
    pub(crate) ttfb_peak: Duration,
    /// Bytes per second.
    pub(crate) rate: Option<Latest<u64>>,
    /// The fastest download, bytes per second.
    pub(crate) rate_peak: u64,
}

impl MirrorPerf {
    fn record_ttfb(&mut self, ttfb: Duration, at: u64) {
        self.ttfb = Some(Latest { value: ttfb, at });
        self.ttfb_peak = self.ttfb_peak.max(ttfb);
    }

    fn record_rate(&mut self, rate: u64, at: u64) {
        self.rate = Some(Latest { value: rate, at });
        self.rate_peak = self.rate_peak.max(rate);
    }
}

/// The newer of two latest samples.
fn newer<T: Copy>(a: Option<Latest<T>>, b: Option<Latest<T>>) -> Option<Latest<T>> {
    match (a, b) {
        (Some(a), Some(b)) => Some(if b.at > a.at { b } else { a }),
        (a, None) => a,
        (None, b) => b,
    }
}

impl Twin for MirrorPerf {
    fn merge(&mut self, other: &Self) {
        let Self {
            ttfb,
            ttfb_peak,
            rate,
            rate_peak,
        } = *other;
        self.ttfb = newer(self.ttfb, ttfb);
        self.ttfb_peak = self.ttfb_peak.max(ttfb_peak);
        self.rate = newer(self.rate, rate);
        self.rate_peak = self.rate_peak.max(rate_peak);
    }
}

static PERF: MirrorRegistry<MirrorPerf> = MirrorRegistry::new(MAX_MIRRORS);

fn now_ticks() -> u64 {
    coarsetime::Instant::now().as_ticks()
}

/// Record the time to first byte of an answered fetch from `mirror`
/// (canonical); see the module doc for which fetches count.
pub(crate) fn record_ttfb(mirror: &Mirror, timing: HeadTiming) {
    let ttfb = timing.ttfb();
    let at = now_ticks();
    PERF.update(mirror, |perf| perf.record_ttfb(ttfb, at));
}

/// Bytes per second of `wire_bytes` over `window`, `None` below
/// [`MIN_THROUGHPUT_BYTES`] or for an empty window.
#[must_use]
fn throughput(wire_bytes: u64, window: Duration) -> Option<u64> {
    if wire_bytes < MIN_THROUGHPUT_BYTES || window.is_zero() {
        return None;
    }
    let rate = u128::from(wire_bytes) * 1_000_000_000 / window.as_nanos();
    Some(u64::try_from(rate).unwrap_or(u64::MAX))
}

/// Record the throughput of a committed download from `mirror`
/// (canonical): `wire_bytes` of body received over `window`, from the
/// parsed head to the last body byte. Small downloads record nothing.
pub(crate) fn record_throughput(mirror: &Mirror, wire_bytes: u64, window: Duration) {
    if let Some(rate) = throughput(wire_bytes, window) {
        let at = now_ticks();
        PERF.update(mirror, |perf| perf.record_rate(rate, at));
    }
}

/// The fastest download recorded from `mirror` (canonical, its twin not
/// merged in), bytes per second; `None` before its first recorded
/// throughput.
#[cfg(feature = "splice")]
#[must_use]
pub(crate) fn peak_throughput(mirror: &Mirror) -> Option<std::num::NonZero<u64>> {
    PERF.get(mirror)
        .and_then(|perf| std::num::NonZero::new(perf.rate_peak))
}

/// Every tracked mirror's figures, keyed by its `host[:port]/path`, for one
/// dashboard render.
#[must_use]
pub(crate) fn snapshot() -> HashMap<Box<str>, MirrorPerf> {
    PERF.snapshot()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn small_downloads_and_empty_windows_record_no_throughput() {
        let second = Duration::from_secs(1);
        assert_eq!(throughput(MIN_THROUGHPUT_BYTES - 1, second), None);
        assert_eq!(throughput(MIN_THROUGHPUT_BYTES, Duration::ZERO), None);
        assert_eq!(
            throughput(MIN_THROUGHPUT_BYTES, second),
            Some(MIN_THROUGHPUT_BYTES)
        );
        assert_eq!(
            throughput(4 * MIN_THROUGHPUT_BYTES, Duration::from_millis(500)),
            Some(8 * MIN_THROUGHPUT_BYTES)
        );
    }

    #[test]
    fn the_latest_sample_and_the_extreme_are_kept() {
        let ms = Duration::from_millis;
        let mut perf = MirrorPerf::default();
        perf.record_ttfb(ms(40), 1);
        perf.record_ttfb(ms(5), 2);
        perf.record_rate(100, 1);
        perf.record_rate(900, 2);
        perf.record_rate(300, 3);
        assert_eq!(perf.ttfb.map(|l| l.value), Some(ms(5)));
        assert_eq!(perf.ttfb_peak, ms(40));
        assert_eq!(perf.rate.map(|l| l.value), Some(300));
        assert_eq!(perf.rate_peak, 900);
    }

    /// Twins fold to the newer latest sample and the more extreme peaks.
    #[test]
    fn twins_merge_to_the_newer_sample() {
        let ms = Duration::from_millis;
        let mut structured = MirrorPerf::default();
        structured.record_ttfb(ms(10), 5);
        let mut flat = MirrorPerf::default();
        flat.record_ttfb(ms(70), 3);
        flat.record_rate(2_000_000, 4);
        structured.merge(&flat);
        assert_eq!(structured.ttfb.map(|l| l.value), Some(ms(10)));
        assert_eq!(structured.ttfb_peak, ms(70));
        assert_eq!(structured.rate.map(|l| l.value), Some(2_000_000));
        assert_eq!(structured.rate_peak, 2_000_000);
    }
}
