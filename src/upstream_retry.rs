//! Upstream connect-retry policy shared by the backends: the attempt budget,
//! the wall-clock budget, the Fibonacci backoff schedule and the
//! `UPSTREAM_RETRIES` accounting. The retry control flow stays
//! backend-specific. The Auto-mode dial of the original scheme is an attempt
//! too, counted by each backend where it dials.

use std::fmt;
use std::time::Duration;

use coarsetime::Instant;

use crate::metrics;

/// Maximum upstream connect *retries*, so a request makes at most
/// `MAX_ATTEMPTS + 1` backoff-paced connect attempts.
pub(crate) const MAX_ATTEMPTS: u32 = 10;

/// Which budget ended the retry loop, for the terminal log line.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RetryLimit {
    Attempts,
    /// The next delay would have run past the wall-clock budget
    /// (`upstream_retry_budget`).
    Budget,
}

impl fmt::Display for RetryLimit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::Attempts => f.write_str("attempt cap reached"),
            Self::Budget => f.write_str("retry budget exhausted"),
        }
    }
}

/// Why connecting stopped: an exhausted budget or a deterministic failure
/// for which the retry policy was never consulted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RetryStop {
    Exhausted(RetryLimit),
    Permanent,
}

impl fmt::Display for RetryStop {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Exhausted(limit) => limit.fmt(f),
            Self::Permanent => f.write_str("permanent failure; not retrying"),
        }
    }
}

impl From<RetryLimit> for RetryStop {
    fn from(limit: RetryLimit) -> Self {
        Self::Exhausted(limit)
    }
}

/// First delay of the schedule, in milliseconds.
const INITIAL_DELAY_MS: u64 = 500;

/// The retry budgets plus a Fibonacci-style connect backoff seeded at 500 ms:
/// 500, 500, 1000, 1500, 2500, 4000, 6500, … ms.
pub(crate) struct Backoff {
    prev: u64,
    curr: u64,
    attempt: u32,
    deadline: Instant,
    /// Whether a granted retry bumps `UPSTREAM_RETRIES`.
    counted: bool,
}

impl Backoff {
    /// `budget` bounds the total retry envelope in wall-clock time, measured
    /// from `now`.
    pub(crate) fn new(budget: Duration, now: Instant) -> Self {
        Self {
            prev: 0,
            curr: INITIAL_DELAY_MS,
            attempt: 1,
            deadline: now.saturating_add(budget.into()),
            counted: true,
        }
    }

    /// [`Self::new`] for traffic no metric describes (hyper's scheme-cache
    /// warm-up): no `UPSTREAM_RETRIES` bumps.
    #[cfg(any(test, feature = "hyper"))]
    pub(crate) fn uncounted(budget: Duration, now: Instant) -> Self {
        Self {
            counted: false,
            ..Self::new(budget, now)
        }
    }

    /// The 1-based number of the attempt currently in flight.
    pub(crate) fn attempt(&self) -> u32 {
        self.attempt
    }

    /// The delay to wait before retrying, or the budget that is spent, on
    /// which the caller must fail terminally.
    ///
    /// The wall-clock rule is "do not start a sleep that finishes past the
    /// deadline". Only the delays are bounded here: each attempt is
    /// separately bounded by `http_timeout`, so a slow connect can still carry
    /// the envelope past the budget before the next check sees it.
    pub(crate) fn next_retry(&mut self, now: Instant) -> Result<Duration, RetryLimit> {
        if self.attempt > MAX_ATTEMPTS {
            return Err(RetryLimit::Attempts);
        }
        let delay = Duration::from_millis(self.curr);
        if now.saturating_add(delay.into()) > self.deadline {
            return Err(RetryLimit::Budget);
        }
        (self.curr, self.prev) = (self.curr + self.prev, self.curr);
        self.attempt += 1;
        if self.counted {
            metrics::UPSTREAM_RETRIES.increment();
        }
        Ok(delay)
    }

    /// Restart the delay schedule without refunding either budget: neither
    /// the attempts already charged nor the wall-clock deadline move.
    #[cfg(any(test, feature = "hyper"))]
    pub(crate) fn reset_delay(&mut self) {
        self.prev = 0;
        self.curr = INITIAL_DELAY_MS;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Large enough that the whole 71.5 s schedule fits: isolates the attempt cap.
    const GENEROUS: Duration = Duration::from_mins(10);

    fn advance(now: Instant, delay: Duration) -> Instant {
        now.saturating_add(delay.into())
    }

    /// Drive the loop the way both backends do: sleep for each returned delay,
    /// then ask again. Returns the delays granted before the terminal error.
    fn drive(budget: Duration) -> (Vec<Duration>, RetryLimit) {
        let start = Instant::now();
        let mut backoff = Backoff::new(budget, start);
        let mut now = start;
        let mut delays = Vec::new();
        loop {
            match backoff.next_retry(now) {
                Ok(delay) => {
                    delays.push(delay);
                    now = advance(now, delay);
                }
                Err(limit) => return (delays, limit),
            }
        }
    }

    fn millis(values: &[u64]) -> Vec<Duration> {
        values.iter().copied().map(Duration::from_millis).collect()
    }

    #[test]
    fn uncounted_backoff_keeps_the_schedule() {
        let now = Instant::now();
        let (mut counted, mut uncounted) = (
            Backoff::new(GENEROUS, now),
            Backoff::uncounted(GENEROUS, now),
        );
        assert!(counted.counted && !uncounted.counted);
        loop {
            let delay = counted.next_retry(now);
            assert_eq!(uncounted.next_retry(now), delay);
            if delay.is_err() {
                break;
            }
        }
    }

    #[test]
    fn backoff_emits_fibonacci_schedule_seeded_at_500() {
        let now = Instant::now();
        let mut b = Backoff::new(GENEROUS, now);
        for want in [500, 500, 1000, 1500, 2500, 4000, 6500] {
            assert_eq!(b.next_retry(now), Ok(Duration::from_millis(want)));
        }
    }

    #[test]
    fn reset_delay_restarts_the_schedule_but_neither_budget() {
        let start = Instant::now();
        let mut b = Backoff::new(Duration::from_secs(30), start);
        let mut now = start;
        for want in [500, 500, 1000] {
            assert_eq!(b.next_retry(now), Ok(Duration::from_millis(want)));
            now = advance(now, Duration::from_millis(want));
        }
        b.reset_delay();
        for want in [500, 500] {
            assert_eq!(b.next_retry(now), Ok(Duration::from_millis(want)));
            now = advance(now, Duration::from_millis(want));
        }
        assert_eq!(b.attempt(), 6);
        // The deadline is still 30s after `start`.
        let near_deadline = advance(start, Duration::from_millis(29_800));
        assert_eq!(b.next_retry(near_deadline), Err(RetryLimit::Budget));
    }

    #[test]
    fn budget_grants_max_attempts_retries_then_gives_up() {
        let now = Instant::now();
        let mut b = Backoff::new(GENEROUS, now);
        assert_eq!(b.attempt(), 1);
        for _ in 0..MAX_ATTEMPTS {
            assert!(b.next_retry(now).is_ok());
        }
        assert_eq!(b.attempt(), MAX_ATTEMPTS + 1);
        assert_eq!(b.next_retry(now), Err(RetryLimit::Attempts));
        assert_eq!(b.next_retry(now), Err(RetryLimit::Attempts));
    }

    #[test]
    fn attempt_cap_applies_when_the_wall_clock_budget_is_generous() {
        let (delays, limit) = drive(GENEROUS);
        assert_eq!(
            delays,
            millis(&[500, 500, 1000, 1500, 2500, 4000, 6500, 10500, 17000, 27500])
        );
        assert_eq!(delays.len(), MAX_ATTEMPTS as usize);
        assert_eq!(limit, RetryLimit::Attempts);
    }

    #[test]
    fn wall_clock_budget_cuts_the_schedule_short() {
        // The default 30s budget: the 9th retry would sleep 17s on top of 27s
        // already elapsed, so it is never started.
        let (delays, limit) = drive(Duration::from_secs(30));
        assert_eq!(
            delays,
            millis(&[500, 500, 1000, 1500, 2500, 4000, 6500, 10500])
        );
        assert!(delays.len() < MAX_ATTEMPTS as usize);
        assert_eq!(delays.iter().sum::<Duration>(), Duration::from_secs(27));
        assert_eq!(limit, RetryLimit::Budget);
    }

    #[test]
    fn budget_below_the_first_delay_yields_no_retries() {
        let now = Instant::now();
        let mut b = Backoff::new(Duration::from_millis(100), now);
        assert_eq!(b.next_retry(now), Err(RetryLimit::Budget));
        assert_eq!(b.attempt(), 1);
    }
}
