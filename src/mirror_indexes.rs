//! How fresh the index each mirror serves is, for the dashboard's Mirrors
//! and Origins tables: a mirror that stopped syncing keeps answering, with
//! an index days or weeks old, and nothing else on the page shows it.
//!
//! Per canonical mirror and suite (`dists/<suite>/`), from the newest
//! `Release`/`InRelease` this process parsed: its `Date:` and `Valid-Until:`
//! and when the mirror last served or confirmed it. The lag -- confirmed
//! minus `Date:` -- is judged at confirmation, not now, so an idle proxy
//! does not make a healthy mirror read stale.
//!
//! Fed by the registry ingest of a structured `Release`/`InRelease`
//! (`integrity::ingest_release_file`, on commit or on a touch of a cached
//! copy the registry lacks), last parsed wins, with the file's mtime as the
//! confirmation time; and by an upstream 304 revalidating one
//! (`integrity::note_release_revalidated`, both backends). A 304 for a suite
//! not recorded yet (the first revalidation after a restart, whose touch
//! ingest is still running) is held as a pending confirmation the ingest
//! applies, so the revalidation time wins over the file's mtime whichever
//! lands first. So nothing is known before the first `apt update` after a
//! restart, and nothing at all without `verify_checksums`, which gates the
//! ingest. Not covered: signatures,
//! per-component `Release` files, flat repositories, cleanup's own `Release`
//! reads.
//!
//! Stored in a [`MirrorRegistry`]; each mirror keeps at most
//! [`MAX_SUITES`].

use hashbrown::HashMap;

use crate::{
    deb_mirror::Mirror,
    index_parser::ReleaseHeader,
    mirror_registry::{MAX_MIRRORS, MirrorRegistry, Twin},
};

/// Suites tracked per mirror. A mirror carries a handful (a release and its
/// `-updates`, `-security`, `-backports` pockets, a few releases); the cap
/// only bounds a client probing made-up suites.
pub(crate) const MAX_SUITES: usize = 64;

/// A freshest suite older than this at its confirmation marks the mirror as
/// behind: two weeks is long past any archive's publishing cycle, yet short
/// of a rarely-publishing vendor repository's quiet spell being mistaken for
/// a sync failure every week.
pub(crate) const BEHIND_AFTER_SECS: u64 = 14 * 24 * 60 * 60;

/// What one parsed `Release`/`InRelease` said about its age.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ReleaseSeen {
    /// Its `Date:` (a far-future one already clamped to absent) and
    /// `Valid-Until:`.
    pub(crate) header: ReleaseHeader,
    /// When the mirror served or confirmed it, unix seconds.
    pub(crate) confirmed_at: i64,
}

/// One suite's newest index.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SuiteIndex {
    pub(crate) date: Option<i64>,
    pub(crate) valid_until: Option<i64>,
    pub(crate) confirmed_at: i64,
}

impl SuiteIndex {
    /// How old the index was when the mirror last served it, in seconds;
    /// `None` without a `Date:`. A date after the confirmation (clock skew)
    /// reads as no lag.
    #[must_use]
    pub(crate) fn lag(self) -> Option<u64> {
        self.date
            .map(|date| u64::try_from(self.confirmed_at.saturating_sub(date)).unwrap_or(0))
    }

    /// Whether the mirror served the index past its `Valid-Until:`, which
    /// makes apt refuse it.
    #[must_use]
    pub(crate) fn expired(self) -> bool {
        self.valid_until
            .is_some_and(|valid_until| valid_until < self.confirmed_at)
    }
}

/// One mirror's suites.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct MirrorIndexes {
    suites: Vec<(Box<str>, SuiteIndex)>,
    /// Confirmations (unix seconds) of suites not recorded yet, applied by
    /// the [`Self::record`] that records them; at most [`MAX_SUITES`].
    pending: Vec<(Box<str>, i64)>,
}

impl MirrorIndexes {
    /// The suites, in the order first seen.
    #[must_use]
    pub(crate) fn suites(&self) -> &[(Box<str>, SuiteIndex)] {
        &self.suites
    }

    /// The suite's entry, if tracked.
    #[must_use]
    pub(crate) fn suite(&self, suite: &str) -> Option<SuiteIndex> {
        self.suites
            .iter()
            .find(|(name, _)| **name == *suite)
            .map(|&(_, index)| index)
    }

    /// Replace (or add, below [`MAX_SUITES`]) the suite's entry. A re-read
    /// of the same index (same dates) never moves its confirmation back:
    /// a touch ingest can read the file's mtime before a 304 that already
    /// confirmed the suite has touched it (or on a filesystem where the
    /// touch cannot land at all).
    ///
    /// A confirmation that arrived before the suite was recorded (see
    /// [`Self::confirm`]) is applied here, the later of the two winning.
    fn record(&mut self, suite: &str, mut index: SuiteIndex) {
        if let Some(pos) = self.pending.iter().position(|(name, _)| **name == *suite) {
            let (_, at) = self.pending.swap_remove(pos);
            index.confirmed_at = index.confirmed_at.max(at);
        }
        if let Some((_, slot)) = self.suites.iter_mut().find(|(name, _)| **name == *suite) {
            let same_index = slot.date == index.date && slot.valid_until == index.valid_until;
            let confirmed_at = if same_index {
                slot.confirmed_at.max(index.confirmed_at)
            } else {
                index.confirmed_at
            };
            *slot = SuiteIndex {
                confirmed_at,
                ..index
            };
        } else if self.suites.len() < MAX_SUITES {
            self.suites.push((Box::from(suite), index));
        }
    }

    /// Move a tracked suite's confirmation to `at`, if later. An untracked
    /// suite keeps `at` pending until [`Self::record`] records it: the 304
    /// that confirmed it can land before the ingest that parses it, and
    /// that ingest dates the index by the file's mtime, which a filesystem
    /// without birth time never moves (`fs_open::touch_volatile_mtime_with`).
    fn confirm(&mut self, suite: &str, at: i64) {
        if let Some((_, slot)) = self.suites.iter_mut().find(|(name, _)| **name == *suite) {
            slot.confirmed_at = slot.confirmed_at.max(at);
        } else if let Some((_, pending)) =
            self.pending.iter_mut().find(|(name, _)| **name == *suite)
        {
            *pending = (*pending).max(at);
        } else if self.pending.len() < MAX_SUITES {
            self.pending.push((Box::from(suite), at));
        }
    }
}

impl Twin for MirrorIndexes {
    /// Per suite, the more recently confirmed entry; pending confirmations
    /// carry over.
    fn merge(&mut self, other: &Self) {
        let Self { suites, pending } = other;
        for (suite, index) in suites {
            match self.suite(suite) {
                Some(own) if own.confirmed_at >= index.confirmed_at => {}
                Some(_) | None => self.record(suite, *index),
            }
        }
        for (suite, at) in pending {
            self.confirm(suite, *at);
        }
    }
}

/// How a mirror's indexes read, worst first.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum IndexState {
    /// A suite was served past its `Valid-Until:`: apt refuses it. Report
    /// it to the mirror, or switch mirrors.
    Expired,
    /// Even the freshest suite was more than [`BEHIND_AFTER_SECS`] old when
    /// served: the mirror has likely stopped syncing.
    Behind,
    Fresh,
}

/// The dashboard's reading of one mirror's indexes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct IndexAge {
    /// The smallest lag over the dated suites: judged by its freshest suite,
    /// a mirror whose release pocket keeps its original `Date:` forever (as
    /// Ubuntu's does) still reads fresh while its `-updates` syncs.
    pub(crate) freshest_lag: Option<u64>,
    pub(crate) state: IndexState,
}

/// Judge a mirror's indexes; `None` without any.
#[must_use]
pub(crate) fn assess(indexes: &MirrorIndexes) -> Option<IndexAge> {
    if indexes.suites.is_empty() {
        return None;
    }
    let freshest_lag = indexes
        .suites
        .iter()
        .filter_map(|(_, index)| index.lag())
        .min();
    let state = if indexes.suites.iter().any(|(_, index)| index.expired()) {
        IndexState::Expired
    } else if freshest_lag.is_some_and(|lag| lag > BEHIND_AFTER_SECS) {
        IndexState::Behind
    } else {
        IndexState::Fresh
    };
    Some(IndexAge {
        freshest_lag,
        state,
    })
}

/// The suite a `Release`'s directory names below `mirror_path`:
/// `debian/dists/bookworm-updates` is `bookworm-updates` for `debian`.
#[must_use]
fn suite_of<'a>(mirror_path: &str, release_dir: &'a str) -> Option<&'a str> {
    let below = if mirror_path.is_empty() {
        release_dir
    } else {
        release_dir.strip_prefix(mirror_path)?.strip_prefix('/')?
    };
    below
        .strip_prefix("dists/")
        .filter(|suite| !suite.is_empty())
}

static INDEXES: MirrorRegistry<MirrorIndexes> = MirrorRegistry::new(MAX_MIRRORS);

/// Record what an ingested `Release` in `release_dir` (host-relative, as the
/// ingest derives it) of `mirror` (canonical) said.
pub(crate) fn record(mirror: &Mirror, release_dir: &str, seen: ReleaseSeen) {
    let Some(suite) = suite_of(mirror.path(), release_dir) else {
        return;
    };
    let ReleaseSeen {
        header: ReleaseHeader { date, valid_until },
        confirmed_at,
    } = seen;
    INDEXES.update(mirror, |indexes| {
        indexes.record(
            suite,
            SuiteIndex {
                date,
                valid_until,
                confirmed_at,
            },
        );
    });
}

/// The mirror confirmed the `Release` in `release_dir` unchanged (an
/// upstream 304) at `at`, unix seconds. A suite not recorded yet gets the
/// confirmation once the touch ingest that follows records it.
pub(crate) fn confirm(mirror: &Mirror, release_dir: &str, at: u64) {
    let Some(suite) = suite_of(mirror.path(), release_dir) else {
        return;
    };
    let at = i64::try_from(at).unwrap_or(i64::MAX);
    INDEXES.update(mirror, |indexes| indexes.confirm(suite, at));
}

/// Every tracked mirror's suites, keyed by its `host[:port]/path`, for one
/// dashboard render.
#[must_use]
pub(crate) fn snapshot() -> HashMap<Box<str>, MirrorIndexes> {
    INDEXES.snapshot()
}

#[cfg(test)]
mod tests {
    use super::*;

    const DAY: i64 = 24 * 60 * 60;
    const NOW: i64 = 1_790_000_000;

    fn index(date: Option<i64>, valid_until: Option<i64>, confirmed_at: i64) -> SuiteIndex {
        SuiteIndex {
            date,
            valid_until,
            confirmed_at,
        }
    }

    fn indexes(suites: &[(&str, SuiteIndex)]) -> MirrorIndexes {
        let mut indexes = MirrorIndexes::default();
        for &(suite, index) in suites {
            indexes.record(suite, index);
        }
        indexes
    }

    #[test]
    fn the_suite_is_the_directory_below_dists() {
        assert_eq!(suite_of("debian", "debian/dists/sid"), Some("sid"));
        assert_eq!(
            suite_of(
                "debian-security",
                "debian-security/dists/bookworm-security/updates"
            ),
            Some("bookworm-security/updates")
        );
        assert_eq!(suite_of("", "dists/noble"), Some("noble"));
        assert_eq!(suite_of("debian", "debianx/dists/sid"), None);
        assert_eq!(suite_of("debian", "debian/pool/sid"), None);
        assert_eq!(suite_of("debian", "debian/dists/"), None);
    }

    /// A release pocket frozen at its original date does not make a mirror
    /// behind while another suite of it is fresh; all suites old does.
    #[test]
    fn a_mirror_is_judged_by_its_freshest_suite() {
        let frozen_and_fresh = indexes(&[
            ("noble", index(Some(NOW - 500 * DAY), None, NOW)),
            ("noble-updates", index(Some(NOW - DAY / 2), None, NOW)),
        ]);
        assert_eq!(
            assess(&frozen_and_fresh),
            Some(IndexAge {
                freshest_lag: Some((DAY / 2).unsigned_abs()),
                state: IndexState::Fresh,
            })
        );
        let stopped = indexes(&[
            ("sid", index(Some(NOW - 20 * DAY), None, NOW)),
            ("experimental", index(Some(NOW - 30 * DAY), None, NOW)),
        ]);
        assert_eq!(
            assess(&stopped).map(|age| age.state),
            Some(IndexState::Behind)
        );
        // Exactly the threshold is not behind yet.
        let edge = indexes(&[("sid", index(Some(NOW - 14 * DAY), None, NOW))]);
        assert_eq!(assess(&edge).map(|age| age.state), Some(IndexState::Fresh));
    }

    /// Serving an index past its Valid-Until is the worst reading, whatever
    /// the dates; a Valid-Until still ahead at confirmation is fine.
    #[test]
    fn an_index_served_past_its_valid_until_is_expired() {
        let expired = indexes(&[
            ("sid", index(Some(NOW - DAY), Some(NOW - 1), NOW)),
            ("experimental", index(Some(NOW - DAY), None, NOW)),
        ]);
        assert_eq!(
            assess(&expired).map(|age| age.state),
            Some(IndexState::Expired)
        );
        let valid = indexes(&[("sid", index(Some(NOW - DAY), Some(NOW + 1), NOW))]);
        assert_eq!(assess(&valid).map(|age| age.state), Some(IndexState::Fresh));
    }

    #[test]
    fn undated_and_future_dated_suites() {
        assert_eq!(assess(&MirrorIndexes::default()), None);
        let undated = indexes(&[("sid", index(None, None, NOW))]);
        assert_eq!(
            assess(&undated),
            Some(IndexAge {
                freshest_lag: None,
                state: IndexState::Fresh,
            })
        );
        // Clock skew: a date after the confirmation is no lag, not a wrap.
        assert_eq!(index(Some(NOW + 60), None, NOW).lag(), Some(0));
    }

    /// Last parsed wins; a 304 only moves the confirmation forward, and
    /// records no suite of its own.
    #[test]
    fn a_suite_is_replaced_by_the_next_parse_and_confirmed_by_a_304() {
        let mut indexes = indexes(&[("sid", index(Some(NOW - DAY), None, NOW - 10))]);
        indexes.confirm("sid", NOW);
        indexes.confirm("sid", NOW - 100);
        indexes.confirm("experimental", NOW);
        assert_eq!(indexes.suite("sid").map(|i| i.confirmed_at), Some(NOW));
        assert_eq!(indexes.suite("experimental"), None);
        indexes.record("sid", index(Some(NOW - 2 * DAY), None, NOW - 5));
        assert_eq!(
            indexes.suite("sid"),
            Some(index(Some(NOW - 2 * DAY), None, NOW - 5))
        );
    }

    /// A 304 for a suite the ingest has not recorded yet (the first
    /// revalidation after a restart) is not lost: the ingest recording the
    /// suite later takes the confirmation over its own, older mtime.
    #[test]
    fn a_confirmation_before_the_first_record_is_applied_by_it() {
        let mut indexes = MirrorIndexes::default();
        indexes.confirm("sid", NOW);
        indexes.confirm("sid", NOW - 100);
        assert_eq!(indexes.suite("sid"), None, "a 304 alone records nothing");
        assert_eq!(assess(&indexes), None);
        // The ingest dates it by an mtime from before the Valid-Until.
        indexes.record("sid", index(Some(NOW - DAY), Some(NOW - 60), NOW - 3600));
        assert_eq!(indexes.suite("sid").map(|i| i.confirmed_at), Some(NOW));
        assert_eq!(
            assess(&indexes).map(|age| age.state),
            Some(IndexState::Expired)
        );
        // Applied once: the next parse stands on its own.
        indexes.record("sid", index(Some(NOW), None, NOW + 10));
        indexes.record("sid", index(Some(NOW + 20), None, NOW + 5));
        assert_eq!(indexes.suite("sid").map(|i| i.confirmed_at), Some(NOW + 5));
    }

    /// A re-read of the same index (a touch ingest reading an mtime from
    /// before the 304 that confirmed it) keeps the later confirmation.
    #[test]
    fn a_reread_of_the_same_index_keeps_its_later_confirmation() {
        let mut indexes = indexes(&[("sid", index(Some(NOW - DAY), Some(NOW + DAY), NOW - 100))]);
        indexes.confirm("sid", NOW);
        indexes.record("sid", index(Some(NOW - DAY), Some(NOW + DAY), NOW - 100));
        assert_eq!(indexes.suite("sid").map(|i| i.confirmed_at), Some(NOW));
    }

    #[test]
    fn suites_are_capped_per_mirror() {
        let mut indexes = MirrorIndexes::default();
        for n in 0..=MAX_SUITES {
            indexes.record(&format!("suite{n}"), index(None, None, NOW));
        }
        assert_eq!(indexes.suites().len(), MAX_SUITES);
        assert_eq!(indexes.suite(&format!("suite{MAX_SUITES}")), None);
    }

    #[test]
    fn twins_keep_the_more_recently_confirmed_suite() {
        let mut structured = indexes(&[
            ("sid", index(Some(NOW - DAY), None, NOW)),
            ("stable", index(Some(NOW - 3 * DAY), None, NOW - 50)),
        ]);
        let flat = indexes(&[
            ("sid", index(Some(NOW - 9 * DAY), None, NOW - 10)),
            ("stable", index(Some(NOW - DAY), None, NOW)),
            ("testing", index(None, None, NOW)),
        ]);
        structured.merge(&flat);
        assert_eq!(
            structured.suite("sid").and_then(|i| i.date),
            Some(NOW - DAY)
        );
        assert_eq!(
            structured.suite("stable").and_then(|i| i.date),
            Some(NOW - DAY)
        );
        assert!(structured.suite("testing").is_some());
    }
}
