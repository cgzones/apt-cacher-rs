use std::sync::LazyLock;

use hashbrown::HashMap;
use http::StatusCode;

use crate::{
    client_info::ClientInfo,
    client_trouble::{self, Trouble},
    config::{ClientHost, DomainName, HostError},
    global_config, metrics,
    request_dispatch::client_permitted,
    warn_once_or_info,
};

#[must_use]
fn is_host_allowed(requested_host: &DomainName) -> bool {
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

/// Reason [`permitted_host`] rejected a host; cached so repeat-spam of the
/// same bad host doesn't re-validate or re-scan `allowed_mirrors`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum HostReject {
    /// Failed `ClientHost::new` — a malformed host, and why.
    Unsupported(HostError),
    /// Validated, but not permitted by `allowed_mirrors`.
    Forbidden,
}

/// Caches the full validation + allow-list check result per raw host
/// string.  On hit, [`permitted_host`] returns a cloned `ClientHost` without
/// re-running `ClientHost::new` or scanning `allowed_mirrors`.
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

/// Validate a raw host (an authority's `host()`, brackets and all) and
/// check it against `allowed_mirrors`, through the cache: the raw spelling
/// is the key, `ClientHost::new` folds it to the canonical host (a
/// bracketed IPv6 authority to its bare address, a DNS name to lowercase).
///
/// The one gate for every host the proxy may fetch from: a request's own
/// ([`authorize_cache_access`]) and a redirect `Location`'s, so a redirect
/// to `[2001:db8::1]` or to `DEB.debian.org` is judged as the canonical
/// host it names. Nothing is logged or counted here: each caller words its
/// own refusal.
pub(crate) fn permitted_host(raw_host: &str) -> Result<ClientHost, HostReject> {
    // Hot path: cache hit returns a cloned ClientHost without
    // re-validating or rescanning allowed_mirrors.
    if let Some(cached) = PERMITTED_HOST_CACHE.lookup(raw_host) {
        return cached;
    }

    // Miss: validate the host and check allowed_mirrors, then cache
    // whatever the outcome was (success, malformed, or not-allowed).
    let result = match ClientHost::new(raw_host) {
        Ok(c) if is_host_allowed(&c) => Ok(c),
        Ok(_) => Err(HostReject::Forbidden),
        Err(err) => Err(HostReject::Unsupported(err)),
    };
    PERMITTED_HOST_CACHE.insert(raw_host.into(), result.clone());
    result
}

pub(crate) fn authorize_cache_access(
    client: &ClientInfo,
    requested_host: &str,
) -> Result<ClientHost, (StatusCode, &'static str)> {
    let config = global_config();

    if !client_permitted(&config.allowed_proxy_clients, client) {
        warn_once_or_info!(
            "Unauthorized proxy client {client}: not permitted by `allowed_proxy_clients`; rejecting with 403"
        );
        metrics::AUTHZ_REJECTED_CLIENT.increment();
        client_trouble::record(client, Trouble::Unauthorized);
        return Err((StatusCode::FORBIDDEN, "Unauthorized client"));
    }

    finalize_host_result(permitted_host(requested_host), requested_host, client)
}

fn finalize_host_result(
    result: Result<ClientHost, HostReject>,
    raw_host: &str,
    client: &ClientInfo,
) -> Result<ClientHost, (StatusCode, &'static str)> {
    match result {
        Ok(d) => Ok(d),
        Err(HostReject::Unsupported(err)) => {
            warn_once_or_info!(
                "Unsupported host `{}` ({err}); rejecting with 400",
                raw_host.escape_debug()
            );
            Err((StatusCode::BAD_REQUEST, "Unsupported host"))
        }
        Err(HostReject::Forbidden) => {
            warn_once_or_info!(
                "Unauthorized host `{}`: not permitted by `allowed_mirrors`; rejecting with 403",
                raw_host.escape_debug()
            );
            metrics::AUTHZ_REJECTED_MIRROR.increment();
            client_trouble::record(client, Trouble::MirrorRefused);
            Err((StatusCode::FORBIDDEN, "Unauthorized host"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The soft cap is enforced by clearing, and only a *new* key past the
    /// cap trips it: re-recording a host already in the map must not throw
    /// away the whole cache.
    #[test]
    fn entry_cap_clears_only_for_a_new_key() {
        let cache = PermittedHostCache::default();
        for i in 0..PERMITTED_HOST_CACHE_MAX_ENTRIES {
            cache.insert(format!("h{i}.invalid").into(), Err(HostReject::Forbidden));
        }
        assert_eq!(cache.entries.read().len(), PERMITTED_HOST_CACHE_MAX_ENTRIES);

        cache.insert(
            "h0.invalid".into(),
            Err(HostReject::Unsupported(HostError::Invalid)),
        );
        assert_eq!(cache.entries.read().len(), PERMITTED_HOST_CACHE_MAX_ENTRIES);
        assert_eq!(
            cache.lookup("h0.invalid"),
            Some(Err(HostReject::Unsupported(HostError::Invalid))),
            "an existing key is overwritten in place"
        );

        cache.insert("overflow.invalid".into(), Err(HostReject::Forbidden));
        assert_eq!(cache.entries.read().len(), 1, "cap clears and starts over");
        assert!(cache.lookup("h0.invalid").is_none());
        assert_eq!(
            cache.lookup("overflow.invalid"),
            Some(Err(HostReject::Forbidden))
        );
    }
}
