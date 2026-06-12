use std::sync::LazyLock;

use hashbrown::HashMap;
use http::StatusCode;

use crate::{ClientInfo, config::ClientHost, global_config, metrics, warn_once_or_info};

#[must_use]
fn is_host_allowed(requested_host: &str) -> bool {
    global_config()
        .allowed_mirrors
        .iter()
        .any(|host| host.permits(requested_host))
}

/// Soft cap on the [`PermittedHostCache`] entry count.  Realistic apt
/// traffic uses a handful of mirrors so this almost never trips; the
/// cap exists purely to bound memory under attacker-driven random
/// `Host:` spam.
const PERMITTED_HOST_CACHE_MAX_ENTRIES: usize = 256;

/// Reason a `Host:` header was rejected by [`authorize_cache_access`];
/// cached so repeat-spam of the same bad host doesn't re-validate or
/// re-scan `allowed_mirrors`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum HostReject {
    /// Failed `ClientHost::new` — malformed `Host:` header.
    Unsupported,
    /// Validated, but not permitted by `allowed_mirrors`.
    Forbidden,
}

/// Caches the full validation + allow-list check result per raw `Host:`
/// string.  On hit, [`authorize_cache_access`] returns a cloned
/// `ClientHost` without re-running `ClientHost::new` or scanning
/// `allowed_mirrors`.
#[derive(Default)]
struct PermittedHostCache {
    entries: parking_lot::RwLock<HashMap<Box<str>, Result<ClientHost, HostReject>>>,
}

impl PermittedHostCache {
    fn lookup(&self, host: &str) -> Option<Result<ClientHost, HostReject>> {
        self.entries.read().get(host).cloned()
    }

    fn insert(&self, host: Box<str>, result: Result<ClientHost, HostReject>) {
        let mut map = self.entries.write();
        if map.len() >= PERMITTED_HOST_CACHE_MAX_ENTRIES && !map.contains_key(host.as_ref()) {
            // Best-effort cap — clear and start over rather than implement
            // proper LRU.  Realistic workloads never hit this; under attack
            // the worst case is "we re-validate everything every N entries"
            // which still beats per-request validation.
            map.clear();
        }
        map.insert(host, result);
    }
}

static PERMITTED_HOST_CACHE: LazyLock<PermittedHostCache> =
    LazyLock::new(PermittedHostCache::default);

/// Cache-aware companion to [`is_host_allowed`] for the moved-host /
/// redirect-destination call sites.  On a hit, returns the cached
/// allow/deny result without re-scanning `allowed_mirrors`.  On a
/// miss, falls through to the uncached scan (these call sites don't
/// have a `ClientHost` to store, so we don't populate the cache here
/// — only [`authorize_cache_access`] does).
#[must_use]
pub(crate) fn is_host_allowed_cached(requested_host: &str) -> bool {
    if let Some(cached) = PERMITTED_HOST_CACHE.lookup(requested_host) {
        return cached.is_ok();
    }
    is_host_allowed(requested_host)
}

pub(crate) fn authorize_cache_access(
    client: &ClientInfo,
    requested_host: &str,
) -> Result<ClientHost, (http::StatusCode, &'static str)> {
    let config = global_config();

    let allowed_proxy_clients = config.allowed_proxy_clients.as_slice();
    let client_ip = client.ip();
    if !allowed_proxy_clients.is_empty()
        && !allowed_proxy_clients
            .iter()
            .any(|ac| ac.contains(&client_ip))
    {
        warn_once_or_info!("Unauthorized proxy client {client}");
        metrics::AUTHZ_REJECTED_CLIENT.increment();
        return Err((StatusCode::FORBIDDEN, "Unauthorized client"));
    }

    // Hot path: cache hit returns a cloned ClientHost without
    // re-validating or rescanning allowed_mirrors.
    if let Some(cached) = PERMITTED_HOST_CACHE.lookup(requested_host) {
        return finalize_host_result(cached, requested_host);
    }

    // Miss: validate the host and check allowed_mirrors, then cache
    // whatever the outcome was (success, malformed, or not-allowed).
    // `ClientHost::new` consumes its argument, so we hand it an owned
    // copy and reuse the original `&str` for the cache key.
    let result = match ClientHost::new(requested_host.to_owned()) {
        Ok(c) if is_host_allowed(&c) => Ok(c),
        Ok(_) => Err(HostReject::Forbidden),
        Err(_) => Err(HostReject::Unsupported),
    };
    PERMITTED_HOST_CACHE.insert(requested_host.into(), result.clone());
    finalize_host_result(result, requested_host)
}

fn finalize_host_result(
    result: Result<ClientHost, HostReject>,
    raw_host: &str,
) -> Result<ClientHost, (http::StatusCode, &'static str)> {
    match result {
        Ok(d) => Ok(d),
        Err(HostReject::Unsupported) => {
            warn_once_or_info!("Unsupported host `{}`", raw_host.escape_debug());
            Err((StatusCode::BAD_REQUEST, "Unsupported host"))
        }
        Err(HostReject::Forbidden) => {
            warn_once_or_info!("Unauthorized host `{}`", raw_host.escape_debug());
            metrics::AUTHZ_REJECTED_MIRROR.increment();
            Err((StatusCode::FORBIDDEN, "Unauthorized host"))
        }
    }
}
