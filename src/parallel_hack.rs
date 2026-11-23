//! The experimental parallel-download hack: answer a cache miss for a large
//! permanent file with a configurable `429` plus `Retry-After` while the
//! proxy keeps downloading, so apt moves on to its next item and late-joins
//! the still-running download on its retry.
//!
//! Backend-neutral on purpose. The gate ([`should_nudge`]), the response head
//! ([`nudge_head`]) and the opening debug line ([`log_nudge`]) are pure
//! functions of the config, so `hyper_conn.rs::serve_new_file` and
//! `splice/mod.rs::splice_proxy` share one decision, one head and one
//! wording instead of two drifting copies. What differs is only who keeps
//! downloading afterwards: hyper's `download_file` is a detached task
//! already, while splice hands the whole download to
//! `splice/detached.rs::DetachedDownload`.

use std::num::NonZero;

use tracing::debug;

use crate::cache_layout::{CachedFlavor, ConnectionDetails};
use crate::config::Config;
use crate::response_head::ResponseHead;

/// Body of the nudge response.
///
/// apt only reaches its transient-error/`Retry-After` path for an error
/// response that *has* a body: `Content-Length: 0` sets
/// `haveContent = TRI_FALSE` and `basehttp.cc:ERROR_UNRECOVERABLE` fails the
/// item permanently. A non-empty body is what makes the nudge a retry rather
/// than a hard failure.
pub(crate) const NUDGE_BODY: &str = "Download in progress";

/// Whether this download answers its client with a nudge instead of the body.
///
/// Volatile resources are never nudged: apt needs the index in hand to decide
/// what to fetch next, so a retry buys nothing. `curr_downloads` includes the
/// caller's own registry entry -- both backends have already originated by
/// the time they ask -- and drives the probability, which decays linearly by
/// `experimental_parallel_hack_factor` per download already in flight and
/// reaches certainty for the first one. It is taken lazily and called at most
/// once, after the enabled, flavor and size checks have passed, so an
/// ineligible request never pays for a registry read.
#[must_use]
pub(crate) fn should_nudge(
    config: &Config,
    flavor: CachedFlavor,
    curr_downloads: impl FnOnce() -> usize,
    total_upper: NonZero<u64>,
) -> bool {
    if flavor == CachedFlavor::Volatile || !config.experimental_parallel_hack_enabled {
        return false;
    }

    if config
        .experimental_parallel_hack_minsize
        .is_some_and(|size| total_upper <= size)
    {
        return false;
    }

    let curr_downloads = curr_downloads();

    if config
        .experimental_parallel_hack_maxparallel
        .is_some_and(|max_parallel| curr_downloads > max_parallel.get())
    {
        return false;
    }

    #[expect(clippy::cast_precision_loss, reason = "generate probability value")]
    let p = (curr_downloads.saturating_sub(1) as f64)
        .mul_add(-config.experimental_parallel_hack_factor, 1.0)
        .max(0.0);
    // `f64()` is uniform in [0, 1): a probability of 1 always nudges, 0 never.
    fastrand::f64() < p
}

/// The head of the nudge response: the configured status code, the configured
/// `Retry-After` and the [`NUDGE_BODY`] length.
///
/// Uses the success header policy: the nudge answers on the origin's
/// behalf and must not advertise `Server:` (see the `response_head` contract).
#[must_use]
pub(crate) fn nudge_head(config: &Config) -> ResponseHead<'static> {
    ResponseHead::nudge(
        config.experimental_parallel_hack_statuscode,
        NUDGE_BODY.len() as u64,
        u32::from(config.experimental_parallel_hack_retryafter),
    )
}

/// The debug line both backends emit right before writing the nudge.
///
/// `prefix` disambiguates the parallel splice/sendfile paths:
/// hyper passes `""`, splice passes `"splice proxy: "`.
pub(crate) fn log_nudge(conn_details: &ConnectionDetails, config: &Config, prefix: &'static str) {
    debug!(
        "{prefix}Trying parallel download hack for client {} and file {} with code {} and retry after value {}",
        conn_details.client,
        conn_details.debname,
        config.experimental_parallel_hack_statuscode,
        config.experimental_parallel_hack_retryafter
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nonzero;

    /// A config with the hack enabled and both size/parallel limits set to
    /// values the callers below pass deliberately.
    fn enabled_config() -> Config {
        let mut config = Config::default();
        config.experimental_parallel_hack_enabled = true;
        config.experimental_parallel_hack_maxparallel = Some(nonzero!(3_usize));
        config.experimental_parallel_hack_minsize = Some(nonzero!(1024_u64));
        config
    }

    /// `should_nudge` is sampled repeatedly so a probability of exactly 0 or 1
    /// is asserted as such rather than as a single lucky draw.
    fn nudges(
        config: &Config,
        flavor: CachedFlavor,
        curr: usize,
        total: NonZero<u64>,
    ) -> Vec<bool> {
        std::iter::repeat_with(|| should_nudge(config, flavor, || curr, total))
            .take(64)
            .collect()
    }

    /// Every case whose probability is exactly 0 or 1.
    #[test]
    fn deterministic_cases_always_or_never_nudge() {
        use CachedFlavor::{Permanent, Volatile};

        let check = |what: &str, config: &Config, flavor, curr, total: u64, expected: bool| {
            let total = NonZero::new(total).expect("nonzero size");
            assert!(
                nudges(config, flavor, curr, total)
                    .iter()
                    .all(|nudged| *nudged == expected),
                "{what} ({curr} downloads, {total} bytes): expected {expected}"
            );
        };

        let enabled = enabled_config();
        check("volatile", &enabled, Volatile, 1, 1_000_000, false);
        check("first download", &enabled, Permanent, 1, 1_000_000, true);
        check("below minsize", &enabled, Permanent, 1, 1, false);
        check("below minsize", &enabled, Permanent, 1, 1023, false);
        check("at minsize", &enabled, Permanent, 1, 1024, false);
        check("above minsize", &enabled, Permanent, 1, 1025, true);
        check("past maxparallel", &enabled, Permanent, 4, 1_000_000, false);

        let mut disabled = enabled_config();
        disabled.experimental_parallel_hack_enabled = false;
        check("disabled", &disabled, Permanent, 1, 1_000_000, false);

        // factor 0.5 with 3 downloads in flight: 1 - 2 * 0.5 == 0.
        let mut decayed = enabled_config();
        decayed.experimental_parallel_hack_factor = 0.5;
        check("decayed to zero", &decayed, Permanent, 3, 1_000_000, false);

        // Without limits only the probability decides: factor 0.2 with one
        // download is 1, and the decay is the only brake.
        let mut unlimited = enabled_config();
        unlimited.experimental_parallel_hack_maxparallel = None;
        unlimited.experimental_parallel_hack_minsize = None;
        check("no limits, first", &unlimited, Permanent, 1, 1, true);
        check("no limits, decayed", &unlimited, Permanent, 999, 1, false);
    }

    #[test]
    fn a_fractional_probability_yields_both_outcomes() {
        // curr=2, factor=0.5: p = 1 - (2-1)*0.5 = 0.5.
        let mut config = enabled_config();
        config.experimental_parallel_hack_factor = 0.5;
        let draws: Vec<bool> = std::iter::repeat_with(|| {
            should_nudge(
                &config,
                CachedFlavor::Permanent,
                || 2,
                nonzero!(1_000_000_u64),
            )
        })
        .take(256)
        .collect();
        assert!(
            draws.iter().any(|nudged| *nudged),
            "a probability of 0.5 must nudge at least once over 256 draws"
        );
        assert!(
            draws.iter().any(|nudged| !nudged),
            "a probability of 0.5 must also skip at least once over 256 draws"
        );
    }

    #[test]
    fn curr_downloads_is_not_called_when_short_circuited() {
        let called = std::cell::Cell::new(false);
        let probe = || {
            called.set(true);
            0_usize
        };

        let mut config = enabled_config();
        config.experimental_parallel_hack_enabled = false;
        let _nudged: bool = should_nudge(
            &config,
            CachedFlavor::Permanent,
            probe,
            nonzero!(1_000_000_u64),
        );
        assert!(
            !called.get(),
            "curr_downloads must not be called when disabled"
        );

        let config = enabled_config();
        let _nudged: bool = should_nudge(
            &config,
            CachedFlavor::Volatile,
            probe,
            nonzero!(1_000_000_u64),
        );
        assert!(
            !called.get(),
            "curr_downloads must not be called for a volatile resource"
        );

        for size in [nonzero!(1_u64), nonzero!(1024_u64)] {
            assert!(!should_nudge(&config, CachedFlavor::Permanent, probe, size));
            assert!(
                !called.get(),
                "curr_downloads must not be called at or below the size threshold"
            );
        }
    }
}
