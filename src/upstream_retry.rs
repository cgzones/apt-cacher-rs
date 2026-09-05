//! Shared upstream connect-retry policy: the attempt budget, the wall-clock
//! budget, the Fibonacci backoff schedule and the `UPSTREAM_RETRIES` accounting
//! used by both the hyper (`request_with_retry`) and splice
//! (`standard_upstream_connect`) backends. The retry *control flow* stays
//! backend-specific; only this policy is shared.

use std::fmt;
use std::time::Duration;

use coarsetime::Instant;

use crate::{metrics, sticky};

/// Maximum upstream connect attempts before giving up (both backends).
/// Enforced by [`Backoff::next_retry`]; exposed only for the cross-module
/// invariant assert in `hyper_conn.rs`.
pub(crate) const MAX_ATTEMPTS: u32 = 10;

/// Which budget ended the retry loop. Reported by [`Backoff::limit`] so the
/// terminal log line tells an operator whether the attempt cap or
/// `upstream_retry_budget` was the limiter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RetryLimit {
    /// All `MAX_ATTEMPTS` retries were spent.
    Attempts,
    /// The next delay would have run past the wall-clock budget.
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

/// First delay of the schedule, in milliseconds, and the value
/// `Backoff::reset_delay` restarts from: keeping both seeds in one place is
/// what makes a reset provably identical to a fresh schedule.
const INITIAL_DELAY_MS: u64 = 500;

/// The retry budgets plus a Fibonacci-style connect backoff seeded at 500 ms:
/// 500, 500, 1000, 1500, 2500, 4000, 6500, … ms. Reproduces the schedule the
/// hyper retry loop has used inline.
pub(crate) struct Backoff {
    prev: u64,
    curr: u64,
    attempt: u32,
    deadline: Instant,
    budget_spent: sticky::Bool,
}

impl Backoff {
    /// `budget` bounds the total retry envelope in wall-clock time, measured
    /// from `now`. The clock is injected rather than read here so the policy
    /// stays unit-testable (same reason as `cleanup::sweep::sweep_candidates`).
    pub(crate) fn new(budget: Duration, now: Instant) -> Self {
        Self {
            prev: 0,
            curr: INITIAL_DELAY_MS,
            attempt: 1,
            deadline: now.saturating_add(budget.into()),
            budget_spent: sticky::Bool::new(),
        }
    }

    /// The 1-based number of the attempt currently in flight — for log messages
    /// and hyper's HTTPS-upgrade revert threshold.
    pub(crate) fn attempt(&self) -> u32 {
        self.attempt
    }

    /// The budget that ended the retry loop, for the terminal log line. Only
    /// meaningful once [`Backoff::next_retry`] has returned `None`.
    pub(crate) fn limit(&self) -> RetryLimit {
        if self.budget_spent.get() {
            RetryLimit::Budget
        } else {
            RetryLimit::Attempts
        }
    }

    /// The delay to wait before retrying, or `None` once the attempt budget OR
    /// the wall-clock budget is spent and the caller must fail terminally.
    /// Charges the attempt, advances the schedule and bumps `UPSTREAM_RETRIES`.
    ///
    /// The wall-clock rule is "do not start a sleep that finishes past the
    /// deadline": a delay ending after `now + budget` (measured from the `now`
    /// passed to [`Backoff::new`]) yields `None` rather than sleeping first and
    /// failing anyway. Only the delays are bounded here — each attempt is
    /// separately bounded by `http_timeout`, so a slow connect can still carry
    /// the envelope past the budget before the next check sees it.
    pub(crate) fn next_retry(&mut self, now: Instant) -> Option<Duration> {
        if self.attempt > MAX_ATTEMPTS {
            return None;
        }
        let delay = Duration::from_millis(self.curr);
        if now.saturating_add(delay.into()) > self.deadline {
            self.budget_spent.set();
            return None;
        }
        (self.curr, self.prev) = (self.curr + self.prev, self.curr);
        self.attempt += 1;
        metrics::UPSTREAM_RETRIES.increment();
        Some(delay)
    }

    /// Restart the delay schedule without refunding either budget — neither the
    /// attempts already charged nor the wall-clock deadline move. Only the
    /// hyper HTTPS-revert branch reuses this; gated so a hyper-less splice build
    /// does not flag it as dead code.
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
    /// then ask again. Returns the delays granted before the terminal `None`.
    fn drive(budget: Duration) -> (Vec<Duration>, RetryLimit) {
        let start = Instant::now();
        let mut backoff = Backoff::new(budget, start);
        let mut now = start;
        let mut delays = Vec::new();
        while let Some(delay) = backoff.next_retry(now) {
            delays.push(delay);
            now = advance(now, delay);
        }
        (delays, backoff.limit())
    }

    fn millis(values: &[u64]) -> Vec<Duration> {
        values.iter().copied().map(Duration::from_millis).collect()
    }

    #[test]
    fn backoff_emits_fibonacci_schedule_seeded_at_500() {
        let now = Instant::now();
        let mut b = Backoff::new(GENEROUS, now);
        for want in [500, 500, 1000, 1500, 2500, 4000, 6500] {
            assert_eq!(b.next_retry(now), Some(Duration::from_millis(want)));
        }
    }

    #[test]
    fn reset_delay_restarts_the_schedule_but_neither_budget() {
        let start = Instant::now();
        let mut b = Backoff::new(Duration::from_secs(30), start);
        let mut now = start;
        for want in [500, 500, 1000] {
            assert_eq!(b.next_retry(now), Some(Duration::from_millis(want)));
            now = advance(now, Duration::from_millis(want));
        }
        b.reset_delay();
        for want in [500, 500] {
            assert_eq!(b.next_retry(now), Some(Duration::from_millis(want)));
            now = advance(now, Duration::from_millis(want));
        }
        // The attempt budget kept counting across the reset.
        assert_eq!(b.attempt(), 6);
        // ... and so did the wall-clock budget: the deadline is still 30s after
        // `start`, so a delay that would run past it is refused.
        let near_deadline = advance(start, Duration::from_millis(29_800));
        assert_eq!(b.next_retry(near_deadline), None);
        assert_eq!(b.limit(), RetryLimit::Budget);
    }

    #[test]
    fn budget_grants_max_attempts_retries_then_gives_up() {
        let now = Instant::now();
        let mut b = Backoff::new(GENEROUS, now);
        assert_eq!(b.attempt(), 1);
        for _ in 0..MAX_ATTEMPTS {
            assert!(b.next_retry(now).is_some());
        }
        // MAX_ATTEMPTS retries after the initial attempt: MAX_ATTEMPTS + 1 connects.
        assert_eq!(b.attempt(), MAX_ATTEMPTS + 1);
        assert_eq!(b.next_retry(now), None);
        assert_eq!(b.next_retry(now), None);
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
        assert_eq!(b.next_retry(now), None);
        assert_eq!(b.attempt(), 1);
        assert_eq!(b.limit(), RetryLimit::Budget);
    }
}
