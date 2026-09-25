//! Per-mirror upstream failure counts since process start, for the
//! dashboard's Mirrors table.
//!
//! The global counters say *that* upstreams fail; these say *which* mirror,
//! so an operator knows where to look, whom to report a bug to, or which
//! mirror to drop. In memory only: a restart forgets them, like every other
//! process-lifetime metric, and no failure text is kept -- the log has it.
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
//! The key is the mirror's `host[:port]/path`, the same rendering as the
//! Mirrors table's `MirrorUri`, so rows join by string. The map only grows on
//! failure paths and is capped at [`MAX_MIRRORS`] distinct mirrors.

use std::sync::LazyLock;

use hashbrown::HashMap;

use crate::deb_mirror::Mirror;

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

/// Distinct mirrors tracked. Mirrors are bounded by `allowed_mirrors` and
/// the paths clients use on them, far below this; the cap only keeps a
/// wildcard allowlist from turning failures into unbounded memory. Failures
/// of a mirror first seen past the cap are not attributed.
const MAX_MIRRORS: usize = 1024;

static HEALTH: LazyLock<parking_lot::Mutex<HashMap<Box<str>, MirrorHealth>>> =
    LazyLock::new(|| parking_lot::Mutex::new(HashMap::new()));

/// The key a mirror's counts are stored under: `host[:port]/path`, the
/// rendering of `database::MirrorUri`.
#[must_use]
pub(crate) fn key(mirror: &Mirror) -> String {
    format!("{}/{}", mirror.format_authority(), mirror.path())
}

/// Count one failed transfer from `mirror` (canonical, alias-resolved).
pub(crate) fn record(mirror: &Mirror, fault: MirrorFault) {
    record_in(&HEALTH, &key(mirror), fault, MAX_MIRRORS);
}

fn record_in(
    map: &parking_lot::Mutex<HashMap<Box<str>, MirrorHealth>>,
    key: &str,
    fault: MirrorFault,
    cap: usize,
) {
    let mut map = map.lock();
    if let Some(health) = map.get_mut(key) {
        health.bump(fault);
    } else if map.len() < cap {
        map.entry(Box::from(key)).or_default().bump(fault);
    }
}

/// Every tracked mirror's counts, for one dashboard render.
#[must_use]
pub(crate) fn snapshot() -> HashMap<Box<str>, MirrorHealth> {
    HEALTH.lock().clone()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn faults_count_per_mirror_and_class() {
        let map = parking_lot::Mutex::new(HashMap::new());
        record_in(&map, "a.example/debian", MirrorFault::Unreachable, 8);
        record_in(&map, "a.example/debian", MirrorFault::Unreachable, 8);
        record_in(&map, "a.example/debian", MirrorFault::Checksum, 8);
        record_in(&map, "b.example/ubuntu", MirrorFault::Slow, 8);
        record_in(&map, "b.example/ubuntu", MirrorFault::Protocol, 8);
        let map = map.into_inner();
        assert_eq!(
            map.get("a.example/debian"),
            Some(&MirrorHealth {
                unreachable: 2,
                protocol: 0,
                checksum: 1,
                slow: 0,
            })
        );
        assert_eq!(
            map.get("b.example/ubuntu"),
            Some(&MirrorHealth {
                unreachable: 0,
                protocol: 1,
                checksum: 0,
                slow: 1,
            })
        );
    }

    #[test]
    fn a_mirror_past_the_cap_is_not_tracked_but_known_ones_still_count() {
        let map = parking_lot::Mutex::new(HashMap::new());
        record_in(&map, "a/", MirrorFault::Slow, 1);
        record_in(&map, "b/", MirrorFault::Slow, 1);
        record_in(&map, "a/", MirrorFault::Slow, 1);
        let map = map.into_inner();
        assert_eq!(map.len(), 1);
        assert_eq!(map.get("a/").map(|h| h.slow), Some(2));
    }

    #[test]
    fn the_key_is_the_mirror_uri_rendering() {
        use crate::{config::ClientHost, deb_mirror::MirrorKind};
        let mirror = Mirror::new(
            ClientHost::new(String::from("deb.example")).expect("valid host"),
            std::num::NonZero::new(8080),
            String::from("debian"),
            MirrorKind::Structured,
        );
        assert_eq!(key(&mirror), "deb.example:8080/debian");
    }
}
