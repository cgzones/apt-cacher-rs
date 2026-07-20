//! Per-source-IP concurrency limiting and active-count tracking for CONNECT
//! tunnels. Shared by every HTTP backend (hyper and sendfile/splice), so it
//! lives at the crate root rather than inside a feature-gated connection
//! module.

use std::net::IpAddr;
use std::num::NonZero;
use std::sync::atomic::{AtomicUsize, Ordering};

use hashbrown::HashMap;

use crate::metrics;

static TUNNEL_CONNECTIONS: std::sync::LazyLock<parking_lot::Mutex<HashMap<IpAddr, usize>>> =
    std::sync::LazyLock::new(|| parking_lot::Mutex::new(HashMap::new()));

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
    let mut map = TUNNEL_CONNECTIONS.lock();
    let count = map.entry(client_ip).or_insert(0);
    if *count >= max.get() {
        return None;
    }
    *count += 1;
    drop(map);
    Some(TunnelGuard { client_ip })
}

pub(crate) struct TunnelGuard {
    client_ip: IpAddr,
}

impl Drop for TunnelGuard {
    fn drop(&mut self) {
        let mut map = TUNNEL_CONNECTIONS.lock();
        if let hashbrown::hash_map::Entry::Occupied(mut entry) = map.entry(self.client_ip) {
            let count = entry.get_mut();
            *count -= 1;
            if *count == 0 {
                entry.remove();
            }
        }
    }
}
