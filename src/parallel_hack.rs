//! The experimental parallel-download hack: answer a cache miss for a large
//! permanent file with a configurable `429` plus `Retry-After` while the
//! proxy keeps downloading, so apt moves on to its next item and late-joins
//! the still-running download on its retry.
//!
//! Backend-neutral on purpose. The gate ([`should_nudge`]), the response head
//! ([`nudge_head`]) and the opening debug line ([`log_nudge`]) are pure
//! functions of the config, so `hyper_conn.rs::serve_new_file` and
//! `splice/mod.rs::splice_proxy_drive` share one decision, one head and one
//! wording instead of two drifting copies. What differs is only who keeps
//! downloading afterwards: hyper's `download_file` is a detached task
//! already, while splice hands the whole download to
//! `splice/detached.rs::DetachedDownload`.

use std::num::NonZero;

use rand::distr::{Bernoulli, Distribution as _};
use tracing::debug;

use crate::cache_layout::{CachedFlavor, ConnectionDetails};
use crate::config::Config;
use crate::response_head::{ResponseHead, ResponseKind};

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
/// once, only once the `enabled`/flavor short-circuit has passed, so a
/// disabled hack or a volatile request never pays for a registry read.
#[must_use]
pub(crate) fn should_nudge(
    config: &Config,
    flavor: CachedFlavor,
    curr_downloads: impl FnOnce() -> usize,
    total_upper: NonZero<u64>,
    rng: &mut impl rand::Rng,
) -> bool {
    if flavor == CachedFlavor::Volatile || !config.experimental_parallel_hack_enabled {
        return false;
    }

    let curr_downloads = curr_downloads();

    if config
        .experimental_parallel_hack_maxparallel
        .is_some_and(|max_parallel| curr_downloads > max_parallel.get())
    {
        return false;
    }
    if config
        .experimental_parallel_hack_minsize
        .is_some_and(|size| total_upper <= size)
    {
        return false;
    }

    #[expect(clippy::cast_precision_loss, reason = "generate probability value")]
    let p = (curr_downloads.saturating_sub(1) as f64)
        .mul_add(-config.experimental_parallel_hack_factor, 1.0)
        .max(0.0);
    let d = Bernoulli::new(p).expect("p is valid");
    d.sample(rng)
}

/// The head of the nudge response: the configured status code, the configured
/// `Retry-After` and the [`NUDGE_BODY`] length.
///
/// [`ResponseKind::Success`] on purpose: the nudge answers on the origin's
/// behalf and must not advertise `Server:` (see the `response_head` contract).
#[must_use]
pub(crate) fn nudge_head(config: &Config) -> ResponseHead<'static> {
    ResponseHead {
        retry_after: Some(u32::from(config.experimental_parallel_hack_retryafter)),
        content_length: Some(NUDGE_BODY.len() as u64),
        ..ResponseHead::bare(
            config.experimental_parallel_hack_statuscode,
            ResponseKind::Success,
        )
    }
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
    use http::StatusCode;
    use rand::{SeedableRng as _, rngs::StdRng};

    use super::*;
    use crate::nonzero;

    /// A config with the hack enabled and both size/parallel limits set to
    /// values the callers below pass deliberately. Built by deserializing an
    /// empty document rather than `Config::default()`, whose `present` field
    /// is private to `config.rs` and so blocks struct-update syntax here.
    fn enabled_config() -> Config {
        let mut config: Config = toml::from_str("").expect("built-in defaults must parse");
        config.experimental_parallel_hack_enabled = true;
        config.experimental_parallel_hack_maxparallel = Some(nonzero!(3_usize));
        config.experimental_parallel_hack_minsize = Some(nonzero!(1024_u64));
        config
    }

    fn rng() -> StdRng {
        StdRng::seed_from_u64(0x5eed_1234)
    }

    /// `should_nudge` is sampled repeatedly so a probability of exactly 0 or 1
    /// is asserted as such rather than as a single lucky draw.
    fn nudges(
        config: &Config,
        flavor: CachedFlavor,
        curr: usize,
        total: NonZero<u64>,
    ) -> Vec<bool> {
        let mut rng = rng();
        std::iter::repeat_with(|| should_nudge(config, flavor, || curr, total, &mut rng))
            .take(64)
            .collect()
    }

    #[test]
    fn disabled_config_never_nudges() {
        let mut config = enabled_config();
        config.experimental_parallel_hack_enabled = false;
        assert!(
            nudges(&config, CachedFlavor::Permanent, 1, nonzero!(1_000_000_u64))
                .iter()
                .all(|nudged| !nudged),
            "a disabled hack must never nudge"
        );
    }

    #[test]
    fn volatile_resources_are_never_nudged() {
        let config = enabled_config();
        assert!(
            nudges(&config, CachedFlavor::Volatile, 1, nonzero!(1_000_000_u64))
                .iter()
                .all(|nudged| !nudged),
            "a volatile resource must never be nudged"
        );
    }

    #[test]
    fn a_file_at_or_below_minsize_is_not_nudged() {
        let config = enabled_config();
        for total in [nonzero!(1_u64), nonzero!(1023_u64), nonzero!(1024_u64)] {
            assert!(
                nudges(&config, CachedFlavor::Permanent, 1, total)
                    .iter()
                    .all(|nudged| !nudged),
                "{total} is not above the 1024 byte minsize"
            );
        }
        assert!(
            nudges(&config, CachedFlavor::Permanent, 1, nonzero!(1025_u64))
                .iter()
                .all(|nudged| *nudged),
            "one byte above minsize is nudged"
        );
    }

    #[test]
    fn more_downloads_than_maxparallel_are_not_nudged() {
        let config = enabled_config();
        assert!(
            nudges(&config, CachedFlavor::Permanent, 4, nonzero!(1_000_000_u64))
                .iter()
                .all(|nudged| !nudged),
            "4 downloads exceed the maxparallel of 3"
        );
    }

    #[test]
    fn the_first_download_is_always_nudged() {
        let config = enabled_config();
        assert!(
            nudges(&config, CachedFlavor::Permanent, 1, nonzero!(1_000_000_u64))
                .iter()
                .all(|nudged| *nudged),
            "the first download has probability 1"
        );
    }

    #[test]
    fn a_probability_decayed_to_zero_never_nudges() {
        // factor 0.5 with 3 downloads in flight: 1 - 2 * 0.5 == 0.
        let mut config = enabled_config();
        config.experimental_parallel_hack_factor = 0.5;
        assert!(
            nudges(&config, CachedFlavor::Permanent, 3, nonzero!(1_000_000_u64))
                .iter()
                .all(|nudged| !nudged),
            "a decayed probability of 0 must never nudge"
        );
    }

    #[test]
    fn absent_limits_skip_their_checks() {
        let mut config = enabled_config();
        config.experimental_parallel_hack_maxparallel = None;
        config.experimental_parallel_hack_minsize = None;
        // Way past what maxparallel would have allowed, and a one-byte file:
        // only the probability decides, and factor 0.2 with 1 download is 1.
        assert!(
            nudges(&config, CachedFlavor::Permanent, 1, nonzero!(1_u64))
                .iter()
                .all(|nudged| *nudged),
            "without limits the first download is still nudged"
        );
        assert!(
            nudges(&config, CachedFlavor::Permanent, 999, nonzero!(1_u64))
                .iter()
                .all(|nudged| !nudged),
            "without maxparallel the probability decay is the only brake"
        );
    }

    #[test]
    fn a_fractional_probability_yields_both_outcomes() {
        // curr=2, factor=0.5: p = 1 - (2-1)*0.5 = 0.5.
        let mut config = enabled_config();
        config.experimental_parallel_hack_factor = 0.5;
        let mut rng = rng();
        let draws: Vec<bool> = std::iter::repeat_with(|| {
            should_nudge(
                &config,
                CachedFlavor::Permanent,
                || 2,
                nonzero!(1_000_000_u64),
                &mut rng,
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
            &mut rng(),
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
            &mut rng(),
        );
        assert!(
            !called.get(),
            "curr_downloads must not be called for a volatile resource"
        );
    }

    #[test]
    fn nudge_head_carries_the_configured_status_and_retry_after() {
        let head = nudge_head(&enabled_config());
        assert_eq!(head.status, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(head.kind, ResponseKind::Success);
        assert_eq!(head.retry_after, Some(5));
        assert_eq!(head.content_length, Some(20));
        assert_eq!(NUDGE_BODY.len(), 20, "the pinned body length");
    }
}
