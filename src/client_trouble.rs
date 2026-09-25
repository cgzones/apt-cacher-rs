//! The clients that cause the most trouble since process start, for the
//! dashboard's Clients table.
//!
//! The global counters say that clients are slow, disconnect, hit a cap or
//! are refused; these say *which* client, so the operator knows whom to look
//! at. Four classes, each pointing at one action:
//!
//! - [`Trouble::Slow`]: a delivery aborted because the client read below
//!   `min_download_rate` or stalled for `http_timeout` (`RATE_LIMIT_CLIENT`,
//!   `HTTP_TIMEOUT_CLIENT_BODY`) -- a slow or stuck client, or a rate floor
//!   set too high for it.
//! - [`Trouble::Disconnect`]: the client went away mid-body
//!   (`CLIENT_DISCONNECTED_MID_BODY`).
//! - [`Trouble::CapRefused`]: a connection or CONNECT tunnel refused by a
//!   per-IP cap (`CONNECTION_REJECTED_PER_IP_CAP`,
//!   `TUNNEL_REJECTED_CAPACITY`) -- a noisy client, or a cap sized below a
//!   NAT gateway's population.
//! - [`Trouble::Unauthorized`]: a request or connection refused by an ACL
//!   or allowlist (`AUTHZ_REJECTED_*`, `CONNECTION_REJECTED_ACL`).
//!
//! Each class is recorded where its global counter is bumped (for the
//! delivery classes, where the failure is concluded), once per event, and
//! never for cleanup's synthetic client.
//!
//! Unlike mirrors, client addresses are unbounded, so the table keeps only
//! the heaviest [`CAPACITY`] hitters with the space-saving algorithm: a
//! newcomer to a full table displaces the entry with the lowest total and
//! inherits that total as its starting weight, so a client that keeps
//! causing trouble rises to the top while one-off noise churns through the
//! bottom slots. A displaced client's counts are lost, and a newcomer's
//! class counts are exact only since it entered (the inherited weight is
//! kept apart as [`ClientTrouble::inherited`]). Only failure and refusal
//! paths touch the table, under one short mutex.

use std::{net::IpAddr, sync::LazyLock};

use crate::client_info::ClientInfo;

/// What kind of trouble a client caused; see the module doc.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Trouble {
    Slow,
    Disconnect,
    CapRefused,
    Unauthorized,
}

/// One tracked client's counts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ClientTrouble {
    pub(crate) ip: IpAddr,
    pub(crate) slow: u64,
    pub(crate) disconnect: u64,
    pub(crate) cap_refused: u64,
    pub(crate) unauthorized: u64,
    /// The total of the entry this one displaced: an upper bound on the
    /// events this client may have caused before it was tracked. 0 for a
    /// client tracked since its first event.
    pub(crate) inherited: u64,
}

impl ClientTrouble {
    /// A client without any trouble: what the Clients table shows for a
    /// persisted client the table does not track.
    #[must_use]
    pub(crate) const fn none(ip: IpAddr) -> Self {
        Self::new(ip, 0)
    }

    const fn new(ip: IpAddr, inherited: u64) -> Self {
        Self {
            ip,
            slow: 0,
            disconnect: 0,
            cap_refused: 0,
            unauthorized: 0,
            inherited,
        }
    }

    /// The weight the table ranks by: the counted events plus the inherited
    /// estimate.
    #[must_use]
    pub(crate) const fn total(&self) -> u64 {
        self.slow + self.disconnect + self.cap_refused + self.unauthorized + self.inherited
    }

    fn bump(&mut self, trouble: Trouble) {
        let Self {
            ip: _,
            slow,
            disconnect,
            cap_refused,
            unauthorized,
            inherited: _,
        } = self;
        let slot = match trouble {
            Trouble::Slow => slow,
            Trouble::Disconnect => disconnect,
            Trouble::CapRefused => cap_refused,
            Trouble::Unauthorized => unauthorized,
        };
        *slot += 1;
    }
}

/// Clients tracked at once.
const CAPACITY: usize = 32;

/// A fixed-capacity space-saving table; linear scans are fine at this size.
struct HeavyHitters {
    entries: Vec<ClientTrouble>,
    capacity: usize,
}

impl HeavyHitters {
    const fn new(capacity: usize) -> Self {
        Self {
            entries: Vec::new(),
            capacity,
        }
    }

    fn record(&mut self, ip: IpAddr, trouble: Trouble) {
        if let Some(entry) = self.entries.iter_mut().find(|e| e.ip == ip) {
            entry.bump(trouble);
            return;
        }
        if self.entries.len() < self.capacity {
            let mut entry = ClientTrouble::new(ip, 0);
            entry.bump(trouble);
            self.entries.push(entry);
            return;
        }
        let Some(lightest) = self.entries.iter_mut().min_by_key(|e| e.total()) else {
            // A zero-capacity table tracks nothing.
            return;
        };
        let mut entry = ClientTrouble::new(ip, lightest.total());
        entry.bump(trouble);
        *lightest = entry;
    }
}

static TABLE: LazyLock<parking_lot::Mutex<HeavyHitters>> =
    LazyLock::new(|| parking_lot::Mutex::new(HeavyHitters::new(CAPACITY)));

/// Count one event against `client`, unless it is cleanup's synthetic one.
pub(crate) fn record(client: &ClientInfo, trouble: Trouble) {
    if client.is_cleanup_synthetic() {
        return;
    }
    record_ip(client.ip(), trouble);
}

/// Count one event against a peer known only by its address (an accept-time
/// refusal, before any request made it a `ClientInfo`). Canonicalized like
/// `ClientInfo::ip`, so an IPv4-mapped peer joins its IPv4 entry.
pub(crate) fn record_ip(ip: IpAddr, trouble: Trouble) {
    TABLE.lock().record(ip.to_canonical(), trouble);
}

/// Every tracked client, heaviest first.
#[must_use]
pub(crate) fn snapshot() -> Vec<ClientTrouble> {
    let mut entries = TABLE.lock().entries.clone();
    entries.sort_unstable_by_key(|e| std::cmp::Reverse(e.total()));
    entries
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(last: u8) -> IpAddr {
        IpAddr::from([192, 0, 2, last])
    }

    #[test]
    fn events_count_per_client_and_class() {
        let mut table = HeavyHitters::new(4);
        table.record(ip(1), Trouble::Slow);
        table.record(ip(1), Trouble::Slow);
        table.record(ip(1), Trouble::Unauthorized);
        table.record(ip(2), Trouble::Disconnect);
        let first = table.entries.iter().find(|e| e.ip == ip(1)).copied();
        assert_eq!(
            first,
            Some(ClientTrouble {
                ip: ip(1),
                slow: 2,
                disconnect: 0,
                cap_refused: 0,
                unauthorized: 1,
                inherited: 0,
            })
        );
        assert_eq!(table.entries.len(), 2);
    }

    #[test]
    fn a_newcomer_displaces_the_lightest_entry_and_inherits_its_weight() {
        let mut table = HeavyHitters::new(2);
        for _ in 0..5 {
            table.record(ip(1), Trouble::CapRefused);
        }
        table.record(ip(2), Trouble::Slow);
        table.record(ip(2), Trouble::Slow);
        // Full: the newcomer replaces ip(2), the lighter of the two.
        table.record(ip(3), Trouble::Disconnect);
        assert!(table.entries.iter().all(|e| e.ip != ip(2)));
        let newcomer = table
            .entries
            .iter()
            .find(|e| e.ip == ip(3))
            .copied()
            .expect("the newcomer is tracked");
        assert_eq!(newcomer.disconnect, 1, "its own events are exact");
        assert_eq!(newcomer.inherited, 2, "it inherits the displaced total");
        assert_eq!(newcomer.total(), 3);
        // The heavy hitter kept its place and its counts.
        assert!(
            table
                .entries
                .iter()
                .any(|e| e.ip == ip(1) && e.cap_refused == 5)
        );
    }

    #[test]
    fn a_persistent_client_climbs_past_one_off_noise() {
        let mut table = HeavyHitters::new(3);
        for noise in 10..40 {
            table.record(ip(noise), Trouble::Unauthorized);
            table.record(ip(1), Trouble::Slow);
        }
        assert!(
            table.entries.iter().any(|e| e.ip == ip(1) && e.slow == 30),
            "the steady offender is never displaced"
        );
    }

    #[test]
    fn the_cleanup_client_is_never_recorded() {
        let before = snapshot();
        record(&ClientInfo::new_cleanup(), Trouble::Slow);
        assert_eq!(snapshot(), before);
    }
}
