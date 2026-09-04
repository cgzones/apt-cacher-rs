//! Per-source-IP concurrency limiting and active-count tracking for CONNECT
//! tunnels. Shared by every HTTP backend (hyper and sendfile/splice), so it
//! lives at the crate root rather than inside a feature-gated connection
//! module.

use std::net::IpAddr;
use std::num::NonZero;
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::{
    metrics,
    per_ip_counter::{PerIpCounter, PerIpPermit},
};

/// No per-IP peak gauge: the dashboard's tunnel peak is the *global*
/// [`metrics::CONNECT_TUNNEL_ACTIVE_PEAK`], maintained by
/// [`ActiveTunnelGuard`] whether or not the per-IP cap is configured.
static TUNNEL_CONNECTIONS: std::sync::LazyLock<PerIpCounter> =
    std::sync::LazyLock::new(|| PerIpCounter::new(None));

/// Total active tunnels across all source IPs. Updated by
/// [`ActiveTunnelGuard`] on every CONNECT regardless of whether the
/// per-IP cap is configured, so the dashboard reflects real activity.
static ACTIVE_TUNNELS: AtomicUsize = AtomicUsize::new(0);

/// Current number of active HTTPS tunnel connections across all clients.
#[must_use]
pub(crate) fn active_tunnels() -> usize {
    ACTIVE_TUNNELS.load(Ordering::Relaxed)
}

/// Unconditionally count an active CONNECT tunnel for the lifetime of
/// this guard. Updates [`metrics::CONNECT_TUNNEL_ACTIVE_PEAK`] on
/// construction.
///
/// Independent from the per-IP rate-limit [`TunnelGuard`] so the
/// dashboard's "active" and "peak" counts are maintained even when
/// `https_tunnel_max_connections_per_client` is unset.
pub(crate) struct ActiveTunnelGuard {
    _private: (),
}

impl ActiveTunnelGuard {
    #[must_use]
    pub(crate) fn new() -> Self {
        let current = ACTIVE_TUNNELS.fetch_add(1, Ordering::Relaxed) + 1;
        metrics::CONNECT_TUNNEL_ACTIVE_PEAK.update(current as u64);
        Self { _private: () }
    }
}

impl Drop for ActiveTunnelGuard {
    fn drop(&mut self) {
        ACTIVE_TUNNELS.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Try to acquire a per-source-IP tunnel slot.
/// Returns `Some(TunnelGuard)` if under the limit, `None` if at capacity.
/// Does *not* update the active-tunnel counter — that's
/// [`ActiveTunnelGuard`]'s job, and the caller composes both guards.
pub(crate) fn try_acquire(client_ip: IpAddr, max: NonZero<usize>) -> Option<TunnelGuard> {
    TUNNEL_CONNECTIONS.try_acquire(client_ip, max)
}

/// A held per-IP tunnel slot; released on drop.
pub(crate) type TunnelGuard = PerIpPermit;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nonzero;

    // `TUNNEL_CONNECTIONS` is process-wide, so every test below uses an IP
    // address no other test touches.

    #[test]
    fn slots_are_capped_per_ip_and_released_on_drop() {
        let ip: IpAddr = "192.0.2.11".parse().expect("test address");

        let first = try_acquire(ip, nonzero!(2)).expect("first slot");
        let second = try_acquire(ip, nonzero!(2)).expect("second slot");
        assert!(
            try_acquire(ip, nonzero!(2)).is_none(),
            "the cap must refuse a third tunnel"
        );

        drop(second);
        let third = try_acquire(ip, nonzero!(2)).expect("a released slot is handed out again");

        drop(first);
        drop(third);
        assert!(
            !TUNNEL_CONNECTIONS.tracks(ip),
            "the last guard's drop must remove the map entry"
        );
    }

    #[test]
    fn one_ip_at_its_cap_does_not_block_another() {
        let busy: IpAddr = "192.0.2.12".parse().expect("test address");
        let other: IpAddr = "192.0.2.13".parse().expect("test address");

        let held = try_acquire(busy, nonzero!(1)).expect("first slot");
        assert!(try_acquire(busy, nonzero!(1)).is_none(), "cap reached");
        let unrelated = try_acquire(other, nonzero!(1)).expect("a different IP is unaffected");

        drop(held);
        drop(unrelated);
    }

    #[test]
    fn the_active_count_follows_the_guard() {
        let before = active_tunnels();
        let guard = ActiveTunnelGuard::new();
        assert_eq!(active_tunnels(), before + 1);
        drop(guard);
        assert_eq!(active_tunnels(), before);
    }
}
