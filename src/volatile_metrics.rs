//! Client-demand diagnostics for volatile indexes. Lookup counts belong to
//! `ConnectionDetails::count_lookup`; admission and revalidation describe
//! subsequent stages, not additional lookups. Cleanup never moves these counters.

use crate::{cache_layout::ConnectionDetails, metrics};

/// Result of attempting to refresh an existing file after an upstream 304.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Renewal {
    Renewed,
    NoBirthTime,
    Failed,
}

impl Renewal {
    pub(crate) fn record(self, details: &ConnectionDetails) {
        if details.client.is_cleanup_synthetic() {
            return;
        }
        match self {
            Self::Renewed => metrics::VOLATILE_RENEWED.increment(),
            Self::NoBirthTime => metrics::VOLATILE_RENEWAL_NO_BTIME.increment(),
            Self::Failed => metrics::VOLATILE_RENEWAL_FAILED.increment(),
        }
    }
}

/// One logical revalidation of a stale copy. Retries and redirects keep the
/// same validators and observation. Completion records the final response head,
/// not body download/commit success. A dropped future is interrupted, not a
/// transport failure; explicit errors call `failed` before returning.
#[derive(Debug)]
pub(crate) struct Revalidation {
    counters: Option<&'static [metrics::Counter; 5]>,
}

impl Revalidation {
    pub(crate) fn new(details: &ConnectionDetails, validators: Option<(bool, bool)>) -> Self {
        Self::with_counters(
            !details.client.is_cleanup_synthetic(),
            validators,
            &metrics::VOLATILE_REVALIDATION,
        )
    }

    fn with_counters(
        enabled: bool,
        validators: Option<(bool, bool)>,
        counters: &'static [[metrics::Counter; 5]; 4],
    ) -> Self {
        let counters = validators.filter(|_| enabled).map(|(etag, modified)| {
            let index = match (etag, modified) {
                (true, false) => 0,
                (false, true) => 1,
                (true, true) => 2,
                (false, false) => 3,
            };
            &counters[index]
        });
        Self { counters }
    }

    pub(crate) fn responded(&mut self, status: u16) {
        self.finish(match status {
            304 => 0,
            200 | 206 => 1,
            _ => 2,
        });
    }

    pub(crate) fn failed(&mut self) {
        self.finish(3);
    }

    fn finish(&mut self, outcome: usize) {
        if let Some(counters) = self.counters.take() {
            counters[outcome].increment();
        }
    }
}

impl Drop for Revalidation {
    fn drop(&mut self) {
        self.finish(4);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn revalidation_counts_once_and_separates_interruptions() {
        let counters = Box::leak(Box::new(metrics::new_revalidation_counters()));
        for (mode, validators) in [(true, false), (false, true), (true, true), (false, false)]
            .into_iter()
            .enumerate()
        {
            for (status, outcome) in [(304, 0), (200, 1), (206, 1), (404, 2)] {
                let mut observation = Revalidation::with_counters(true, Some(validators), counters);
                observation.responded(status);
                // No second terminal outcome, including Drop, may count.
                observation.failed();
                drop(observation);
                assert_eq!(
                    counters[mode][outcome].get(),
                    if status == 206 { 2 } else { 1 }
                );
            }
            let mut failure = Revalidation::with_counters(true, Some(validators), counters);
            failure.failed();
            drop(failure);
            drop(Revalidation::with_counters(
                true,
                Some(validators),
                counters,
            ));
            assert_eq!(counters[mode][3].get(), 1);
            assert_eq!(counters[mode][4].get(), 1);
        }
        for (enabled, validators) in [(false, Some((true, true))), (true, None)] {
            let mut excluded = Revalidation::with_counters(enabled, validators, counters);
            excluded.responded(304);
        }
        assert_eq!(
            counters[2][0].get(),
            1,
            "cleanup and missing copies do not revalidate"
        );
    }
    #[test]
    fn volatile_diagnostics_exclude_cleanup_requests() {
        use crate::cache_layout::{FetchRole, LookupOutcome, MissReason, ResourceKind};
        let snapshot = || {
            let mut values = vec![
                metrics::VOLATILE_HIT.get(),
                metrics::VOLATILE_REFETCHED.get(),
                metrics::VOLATILE_ABSENT.get(),
                metrics::VOLATILE_EXPIRED.get(),
                metrics::VOLATILE_FUTURE.get(),
                #[cfg(feature = "sendfile")]
                metrics::VOLATILE_IN_FLIGHT.get(),
                metrics::VOLATILE_ORIGINATORS.get(),
                metrics::VOLATILE_JOINERS.get(),
                metrics::VOLATILE_ADMISSION_REFUSED.get(),
                metrics::VOLATILE_RENEWED.get(),
                metrics::VOLATILE_RENEWAL_NO_BTIME.get(),
                metrics::VOLATILE_RENEWAL_FAILED.get(),
            ];
            values.extend(
                metrics::VOLATILE_REVALIDATION
                    .iter()
                    .flatten()
                    .map(metrics::Counter::get),
            );
            values
        };
        let mut details = crate::test_support::connection_details("sid_Release");
        details.resource_kind = ResourceKind::Release;
        details.client = crate::client_info::ClientInfo::new_cleanup();
        let before = snapshot();
        details.count_lookup(LookupOutcome::Hit);
        for reason in [
            MissReason::Absent,
            MissReason::Expired,
            MissReason::FutureTimestamp,
            #[cfg(feature = "sendfile")]
            MissReason::InFlight,
        ] {
            details.count_lookup(LookupOutcome::Miss(reason));
        }
        for role in [FetchRole::Originator, FetchRole::Joiner, FetchRole::Refused] {
            details.count_fetch_role(role);
        }
        for renewal in [Renewal::Renewed, Renewal::NoBirthTime, Renewal::Failed] {
            renewal.record(&details);
        }
        let mut observation = Revalidation::new(&details, Some((true, true)));
        observation.responded(304);
        drop(observation);
        assert_eq!(
            snapshot(),
            before,
            "synthetic cleanup must leave client diagnostics untouched"
        );
    }
}
