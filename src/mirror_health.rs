//! Per-mirror upstream failure counts since process start, for the
//! dashboard's Mirrors table.
//!
//! The global counters say *that* upstreams fail; these say *which* mirror,
//! so an operator knows where to look, whom to report a bug to, or which
//! mirror to drop. No failure text is kept -- the log has it.
//!
//! Each class is recorded once per failed transfer, at the one place the
//! transfer's failure is concluded with its canonical mirror in scope:
//! `DownloadFailure::conclude` for every registered download (both
//! backends, cleanup's hyper index fetches included), `UpstreamError::conclude`
//! for splice's cleanup fetches, `RejectReason::record_metrics` for an
//! upstream answer the planner refuses (an unsolicited 206, missing
//! framing), and the commit (`guards::RenameBarrier::commit`) and cleanup
//! verify for checksum mismatches. Passthrough relays -- and the body of a
//! cached route's answer relayed uncached -- are not attributed: a
//! passthrough's path is not split into mirror and resource, and hyper's
//! relay has no mirror at all, so attributing splice's alone would make the
//! backends disagree.
//!
//! Stored in a [`MirrorRegistry`] (keying, the snapshot's `host[:port]/path`
//! rendering, the cap); the map only grows on failure paths.

use hashbrown::HashMap;

use crate::{
    deb_mirror::Mirror,
    mirror_registry::{MAX_MIRRORS, MirrorRegistry, Twin},
};

/// What a failed transfer tells the operator about its mirror.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MirrorFault {
    /// The connect or the exchange before a response head failed: the
    /// mirror is down or unreachable from here.
    Unreachable,
    /// The mirror broke the HTTP contract (a malformed head, a body that
    /// disagrees with its framing, an unsolicited 206): a bug to report.
    Protocol,
    /// A complete body did not match its index's digest, at download or at
    /// cleanup's re-verification: the mirror serves content its own index
    /// disagrees with.
    Checksum,
    /// A body read timed out or the transfer fell below
    /// `min_download_rate`: the mirror (or the path to it) is too slow.
    Slow,
}

/// One mirror's failure counts since process start.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct MirrorHealth {
    pub(crate) unreachable: u64,
    pub(crate) protocol: u64,
    pub(crate) checksum: u64,
    pub(crate) slow: u64,
}

impl MirrorHealth {
    fn bump(&mut self, fault: MirrorFault) {
        let Self {
            unreachable,
            protocol,
            checksum,
            slow,
        } = self;
        let slot = match fault {
            MirrorFault::Unreachable => unreachable,
            MirrorFault::Protocol => protocol,
            MirrorFault::Checksum => checksum,
            MirrorFault::Slow => slow,
        };
        *slot += 1;
    }
}

impl Twin for MirrorHealth {
    fn merge(&mut self, other: &Self) {
        let Self {
            unreachable,
            protocol,
            checksum,
            slow,
        } = *other;
        self.unreachable += unreachable;
        self.protocol += protocol;
        self.checksum += checksum;
        self.slow += slow;
    }
}

static HEALTH: MirrorRegistry<MirrorHealth> = MirrorRegistry::new(MAX_MIRRORS);

/// Count one failed transfer from `mirror` (canonical, alias-resolved).
pub(crate) fn record(mirror: &Mirror, fault: MirrorFault) {
    HEALTH.update(mirror, |health| health.bump(fault));
}

/// Every tracked mirror's counts, keyed by its `host[:port]/path`, for one
/// dashboard render.
#[must_use]
pub(crate) fn snapshot() -> HashMap<Box<str>, MirrorHealth> {
    HEALTH.snapshot()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{config::ClientHost, deb_mirror::MirrorKind};

    #[test]
    fn faults_count_per_class_and_twins_add_up() {
        let mut health = MirrorHealth::default();
        health.bump(MirrorFault::Unreachable);
        health.bump(MirrorFault::Unreachable);
        health.bump(MirrorFault::Checksum);
        let mut twin = MirrorHealth::default();
        twin.bump(MirrorFault::Slow);
        twin.bump(MirrorFault::Protocol);
        health.merge(&twin);
        assert_eq!(
            health,
            MirrorHealth {
                unreachable: 2,
                protocol: 1,
                checksum: 1,
                slow: 1,
            }
        );
    }

    #[test]
    fn the_snapshot_key_is_the_mirror_uri_rendering() {
        let mirror = Mirror::new(
            ClientHost::new(String::from("health-key.example")).expect("valid host"),
            std::num::NonZero::new(8080),
            String::from("debian"),
            MirrorKind::Structured,
        );
        record(&mirror, MirrorFault::Slow);
        assert_eq!(
            snapshot()
                .get("health-key.example:8080/debian")
                .map(|h| h.slow),
            Some(1)
        );
    }
}
