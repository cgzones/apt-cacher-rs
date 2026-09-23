//! Which cached index files the checksum registry currently holds the
//! digests of, so an index answered from cache is re-ingested exactly when
//! its digests are missing (restart, eviction, a skipped or failed ingest).
//!
//! Pure bookkeeping, no I/O and no globals: `integrity` owns the one
//! instance and runs the ingests. Keyed by the index's cache path. A path is
//! `Running` while one ingest task owns it, which is also the dedupe: a
//! second claim of a running path is refused. A commit that replaces the
//! file while its ingest runs sets `rerun`, and the owner runs again instead
//! of marking the old file's result on the new one.
//!
//! `Ingested` records the registry scope's eviction epoch at the start of
//! the run; a later eviction from that scope bumps the epoch, and a mark
//! from an older epoch no longer counts. That is the scope-wide unmark,
//! without walking the ledger.
//!
//! At the cap, [`IngestLedger::claim`]'s overflow clear keeps only `Running`
//! entries and drops every other mark, `Failed` included: a path marked
//! failed can therefore be decoded once more after an overflow evicts its
//! entry, and fail again deterministically. CPU stays bounded regardless --
//! `integrity`'s decode permits (`PACKAGES_INGEST_PERMITS`) cap concurrent
//! decodes independently of how many paths the ledger currently tracks.

use std::path::{Path, PathBuf};

use hashbrown::HashMap;
use parking_lot::Mutex;

/// What one ingest run concluded about its file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Outcome {
    /// Every digest was registered.
    Ingested,
    /// The file can never ingest (too large, corrupt, over the CPU budget);
    /// not retried until a commit replaces it.
    Failed,
    /// Not ingested for a reason that may pass (queue full, an I/O error);
    /// the next claim runs it again.
    Retry,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    Unmarked,
    Ingested { epoch: u64 },
    Failed,
    Running { rerun: bool, epoch_at_start: u64 },
}

/// See the module doc.
#[derive(Debug)]
pub(crate) struct IngestLedger {
    paths: Mutex<HashMap<PathBuf, State>>,
    cap: usize,
}

impl IngestLedger {
    pub(crate) fn new(cap: usize) -> Self {
        Self {
            paths: Mutex::new(HashMap::new()),
            cap,
        }
    }

    /// Claim `path` for an ingest run, `epoch` being its registry scope's
    /// current eviction epoch. `None` when there is nothing to do: the file
    /// is ingested under this epoch, failed, or already being ingested.
    ///
    /// At the cap, every entry but the running ones is dropped first: a
    /// running entry's task still owns its path, and dropping it would let
    /// a second task ingest the same path and lose a pending rerun.
    pub(crate) fn claim(&self, path: &Path, epoch: u64) -> Option<Claim<'_>> {
        let running = State::Running {
            rerun: false,
            epoch_at_start: epoch,
        };
        let mut paths = self.paths.lock();
        if let Some(state) = paths.get_mut(path) {
            match *state {
                State::Unmarked => {}
                State::Ingested { epoch: marked } if marked != epoch => {}
                State::Ingested { .. } | State::Failed | State::Running { .. } => return None,
            }
            *state = running;
        } else {
            if paths.len() >= self.cap {
                paths.retain(|_, state| matches!(state, State::Running { .. }));
            }
            paths.insert(path.to_path_buf(), running);
        }
        drop(paths);
        Some(Claim {
            ledger: self,
            path: path.to_path_buf(),
            open: true,
        })
    }

    /// A commit replaced the file at `path`: forget its mark, or tell its
    /// running ingest to run again on the new file.
    pub(crate) fn invalidate(&self, path: &Path) {
        if let Some(state) = self.paths.lock().get_mut(path) {
            match state {
                State::Running {
                    rerun,
                    epoch_at_start: _,
                } => *rerun = true,
                State::Unmarked | State::Ingested { .. } | State::Failed => {
                    *state = State::Unmarked;
                }
            }
        }
    }

    /// Settle a claimed path. `true` when the caller must run again.
    fn settle(&self, path: &Path, outcome: Outcome, epoch: u64) -> bool {
        let mut paths = self.paths.lock();
        let Some(state) = paths.get_mut(path) else {
            return false;
        };
        let State::Running {
            rerun,
            epoch_at_start,
        } = *state
        else {
            return false;
        };
        if rerun {
            *state = State::Running {
                rerun: false,
                epoch_at_start: epoch,
            };
            return true;
        }
        *state = match outcome {
            Outcome::Ingested if epoch == epoch_at_start => State::Ingested { epoch },
            Outcome::Ingested | Outcome::Retry => State::Unmarked,
            Outcome::Failed => State::Failed,
        };
        drop(paths);
        false
    }

    #[cfg(test)]
    fn state(&self, path: &Path) -> Option<State> {
        self.paths.lock().get(path).copied()
    }
}

/// Ownership of one claimed path's run. Dropped without a final
/// [`Self::finish`] (a panic, runtime shutdown), it leaves the path
/// unmarked, so the next claim runs it instead of finding it `Running`
/// forever.
#[derive(Debug)]
pub(crate) struct Claim<'a> {
    ledger: &'a IngestLedger,
    path: PathBuf,
    open: bool,
}

impl Claim<'_> {
    /// Record the run's outcome under the scope's current `epoch`. `true`
    /// when the file was replaced during the run: the caller runs again,
    /// still owning the path.
    pub(crate) fn finish(&mut self, outcome: Outcome, epoch: u64) -> bool {
        let again = self.ledger.settle(&self.path, outcome, epoch);
        self.open = again;
        again
    }
}

impl Drop for Claim<'_> {
    fn drop(&mut self) {
        if self.open
            && let Some(state) = self.ledger.paths.lock().get_mut(&self.path)
        {
            *state = State::Unmarked;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(name: &str) -> PathBuf {
        PathBuf::from(format!("/cache/{name}"))
    }

    #[test]
    fn an_ingested_path_is_not_claimed_again_under_the_same_epoch() {
        let ledger = IngestLedger::new(16);
        let mut claim = ledger.claim(&p("a"), 0).expect("first claim");
        assert!(!claim.finish(Outcome::Ingested, 0));
        drop(claim);
        assert!(ledger.claim(&p("a"), 0).is_none());
        assert_eq!(ledger.state(&p("a")), Some(State::Ingested { epoch: 0 }));
    }

    #[test]
    fn an_eviction_epoch_bump_makes_the_mark_stale() {
        let ledger = IngestLedger::new(16);
        let mut claim = ledger.claim(&p("a"), 0).expect("first claim");
        assert!(!claim.finish(Outcome::Ingested, 0));
        drop(claim);
        assert!(ledger.claim(&p("a"), 1).is_some(), "epoch 1 > mark 0");
    }

    #[test]
    fn an_eviction_during_the_run_leaves_the_path_unmarked() {
        let ledger = IngestLedger::new(16);
        let mut claim = ledger.claim(&p("a"), 0).expect("claim");
        assert!(!claim.finish(Outcome::Ingested, 1));
        drop(claim);
        assert_eq!(ledger.state(&p("a")), Some(State::Unmarked));
    }

    #[test]
    fn a_running_path_is_not_claimed_twice() {
        let ledger = IngestLedger::new(16);
        let _claim = ledger.claim(&p("a"), 0).expect("claim");
        assert!(ledger.claim(&p("a"), 0).is_none());
    }

    #[test]
    fn a_failed_path_stays_failed_until_invalidated() {
        let ledger = IngestLedger::new(16);
        let mut claim = ledger.claim(&p("a"), 0).expect("claim");
        assert!(!claim.finish(Outcome::Failed, 0));
        drop(claim);
        assert!(ledger.claim(&p("a"), 7).is_none(), "no epoch revives it");
        ledger.invalidate(&p("a"));
        assert!(ledger.claim(&p("a"), 7).is_some(), "a commit does");
    }

    #[test]
    fn a_retry_outcome_is_claimable_again() {
        let ledger = IngestLedger::new(16);
        let mut claim = ledger.claim(&p("a"), 0).expect("claim");
        assert!(!claim.finish(Outcome::Retry, 0));
        drop(claim);
        assert!(ledger.claim(&p("a"), 0).is_some());
    }

    #[test]
    fn commit_during_run_requests_a_rerun() {
        let ledger = IngestLedger::new(16);
        let mut claim = ledger.claim(&p("a"), 0).expect("claim");
        ledger.invalidate(&p("a"));
        assert!(claim.finish(Outcome::Ingested, 0), "replaced mid-run");
        assert_eq!(
            ledger.state(&p("a")),
            Some(State::Running {
                rerun: false,
                epoch_at_start: 0
            })
        );
        assert!(ledger.claim(&p("a"), 0).is_none(), "still owned");
        assert!(!claim.finish(Outcome::Ingested, 0));
        assert_eq!(ledger.state(&p("a")), Some(State::Ingested { epoch: 0 }));
    }

    #[test]
    fn invalidate_unmarks_an_ingested_path() {
        let ledger = IngestLedger::new(16);
        let mut claim = ledger.claim(&p("a"), 0).expect("claim");
        assert!(!claim.finish(Outcome::Ingested, 0));
        drop(claim);
        ledger.invalidate(&p("a"));
        assert_eq!(ledger.state(&p("a")), Some(State::Unmarked));
        ledger.invalidate(&p("never-seen"));
        assert_eq!(ledger.state(&p("never-seen")), None);
    }

    #[test]
    fn dropped_claim_leaves_the_path_unmarked() {
        let ledger = IngestLedger::new(16);
        drop(ledger.claim(&p("a"), 0).expect("claim"));
        assert_eq!(ledger.state(&p("a")), Some(State::Unmarked));
        assert!(ledger.claim(&p("a"), 0).is_some());
    }

    #[test]
    fn overflow_drops_idle_entries_but_keeps_running_ones() {
        let ledger = IngestLedger::new(2);
        let running = ledger.claim(&p("run"), 0).expect("claim");
        let mut done = ledger.claim(&p("done"), 0).expect("claim");
        assert!(!done.finish(Outcome::Ingested, 0));
        drop(done);
        let _third = ledger.claim(&p("third"), 0).expect("claim at the cap");
        assert_eq!(ledger.state(&p("done")), None, "idle entry dropped");
        assert!(matches!(
            ledger.state(&p("run")),
            Some(State::Running { .. })
        ));
        ledger.invalidate(&p("run"));
        drop(running);
        assert_eq!(ledger.state(&p("run")), Some(State::Unmarked));
    }
}
