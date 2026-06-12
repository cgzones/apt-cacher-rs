use std::{
    net::IpAddr,
    num::NonZero,
    sync::atomic::{AtomicUsize, Ordering},
};

use hashbrown::HashMap;

use crate::metrics;

static CONNECTED_CLIENTS: AtomicUsize = AtomicUsize::new(0);
static CLIENT_DOWNLOADS: AtomicUsize = AtomicUsize::new(0);

static CONNECTIONS_PER_IP: std::sync::LazyLock<parking_lot::Mutex<HashMap<IpAddr, usize>>> =
    std::sync::LazyLock::new(|| parking_lot::Mutex::new(HashMap::new()));

#[must_use]
pub(crate) fn connected_clients() -> usize {
    CONNECTED_CLIENTS.load(Ordering::Relaxed)
}

pub(crate) struct ClientCounter {
    client_ip: IpAddr,
    /// `true` iff `try_new` inserted/incremented an entry in
    /// `CONNECTIONS_PER_IP`. When `false`, `Drop` skips the mutex
    /// acquire entirely — the no-cap deployment path is then a single
    /// atomic decrement.
    tracked_per_ip: bool,
}

impl ClientCounter {
    pub(crate) fn try_new(client_ip: IpAddr, max_per_ip: Option<NonZero<usize>>) -> Option<Self> {
        let tracked_per_ip = if let Some(max) = max_per_ip {
            let mut map = CONNECTIONS_PER_IP.lock();
            let count = map.entry(client_ip).or_insert(0);
            if *count >= max.get() {
                drop(map);
                metrics::CONNECTION_REJECTED_PER_IP_CAP.increment();
                return None;
            }
            *count += 1;
            let observed = *count as u64;
            drop(map);
            metrics::PER_CLIENT_IP_PEAK.update(observed);
            true
        } else {
            false
        };
        let current = CONNECTED_CLIENTS.fetch_add(1, Ordering::Relaxed) + 1;
        metrics::CONNECTED_CLIENTS_PEAK.update(current as u64);
        Some(Self {
            client_ip,
            tracked_per_ip,
        })
    }
}

impl Drop for ClientCounter {
    fn drop(&mut self) {
        CONNECTED_CLIENTS.fetch_sub(1, Ordering::Relaxed);
        if !self.tracked_per_ip {
            return;
        }
        let mut map = CONNECTIONS_PER_IP.lock();
        if let hashbrown::hash_map::Entry::Occupied(mut entry) = map.entry(self.client_ip) {
            let count = entry.get_mut();
            *count -= 1;
            if *count == 0 {
                entry.remove();
            }
        }
    }
}

#[must_use]
pub(crate) fn active_client_downloads() -> usize {
    CLIENT_DOWNLOADS.load(Ordering::Relaxed)
}

#[derive(Debug)]
pub(crate) struct ClientDownload {
    _private: (),
}

impl ClientDownload {
    pub(crate) fn new() -> Self {
        let current = CLIENT_DOWNLOADS.fetch_add(1, Ordering::Relaxed) + 1;
        metrics::ACTIVE_CLIENT_DOWNLOADS_PEAK.update(current as u64);
        Self { _private: () }
    }
}

impl Drop for ClientDownload {
    fn drop(&mut self) {
        CLIENT_DOWNLOADS.fetch_sub(1, Ordering::Relaxed);
    }
}
