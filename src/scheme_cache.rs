//! Process-wide upstream-scheme cache and the shared HTTP-vs-HTTPS decision
//! logic used by both the hyper and splice backends.
//!
//! The retry/revert machinery (hyper `inner_loop`) and the connect-with-fallback
//! flow (splice `connect_upstream`) stay backend-specific — this module owns the
//! scheme types, the decision (`resolve`/`decide`), and the cache read/insert/evict
//! (`record_success`/`record_failure`).

use std::fmt::Display;
use std::num::NonZero;
use std::sync::OnceLock;

use hashbrown::{Equivalent, HashMap, hash_map::EntryRef};
use http::uri::Authority;
use parking_lot::RwLock;

use crate::config::{Config, HttpsUpgradeMode};
use crate::deb_mirror::Mirror;
use crate::metrics;

/// Upstream URI scheme we support proxying.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) enum Scheme {
    Http,
    Https,
}

impl Display for Scheme {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Http => "http",
            Self::Https => "https",
        })
    }
}

impl From<Scheme> for http::uri::Scheme {
    fn from(scheme: Scheme) -> Self {
        match scheme {
            Scheme::Http => Self::HTTP,
            Scheme::Https => Self::HTTPS,
        }
    }
}

impl Scheme {
    /// Map an HTTP(S) URI scheme back to a `Scheme`; `None` for any other scheme.
    pub(crate) fn from_uri_scheme(s: &http::uri::Scheme) -> Option<Self> {
        if *s == http::uri::Scheme::HTTPS {
            Some(Self::Https)
        } else if *s == http::uri::Scheme::HTTP {
            Some(Self::Http)
        } else {
            None
        }
    }
}

/// Owned `(host, port)` key for the scheme cache and the kTLS block-list.
#[derive(Debug, Eq, Hash, PartialEq)]
pub(crate) struct SchemeKey {
    pub(crate) host: String,
    pub(crate) port: Option<u16>,
}

/// Borrowed lookup key, so hot-path reads avoid allocating a `SchemeKey`.
#[derive(Copy, Clone, Hash)]
pub(crate) struct SchemeKeyRef<'a> {
    pub(crate) host: &'a str,
    pub(crate) port: Option<u16>,
}

/// The splice backend keys on a `Mirror`, the hyper backend on a request
/// `Authority`; both project to the same borrowed `(host, port)` pair.
impl<'a> From<&'a Mirror> for SchemeKeyRef<'a> {
    fn from(mirror: &'a Mirror) -> Self {
        Self {
            host: mirror.host().as_str(),
            port: mirror.port().map(NonZero::get),
        }
    }
}

impl<'a> From<&'a Authority> for SchemeKeyRef<'a> {
    fn from(auth: &'a Authority) -> Self {
        Self {
            host: auth.host(),
            port: auth.port_u16(),
        }
    }
}

impl Equivalent<SchemeKey> for SchemeKeyRef<'_> {
    fn equivalent(&self, key: &SchemeKey) -> bool {
        let &Self { host, port } = self;
        let SchemeKey {
            host: khost,
            port: kport,
        } = key;
        host == khost && port == *kport
    }
}

/// Process-wide cache of the scheme last known good for each upstream host.
/// Module-private: reach it only through [`cache`] and the functions below.
static SCHEME_CACHE: OnceLock<RwLock<HashMap<SchemeKey, Scheme>>> = OnceLock::new();

fn cache() -> &'static RwLock<HashMap<SchemeKey, Scheme>> {
    SCHEME_CACHE.get_or_init(|| RwLock::new(HashMap::new()))
}

/// Debug-format the current cache contents, for the startup warm-up trace.
#[cfg(feature = "hyper")]
pub(crate) fn debug_contents() -> String {
    format!("{:?}", *cache().read())
}

/// The scheme decision for one upstream request, richer than a bare `Scheme` so
/// hyper can tell an HTTPS *upgrade attempt* (which sets `https_upgrade_test`
/// and bumps `HTTPS_UPGRADE_ATTEMPTED`) apart from a fixed HTTPS scheme, while
/// splice collapses it back to its `Option<Scheme>` view via [`fixed_scheme`].
///
/// [`fixed_scheme`]: SchemeDecision::fixed_scheme
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) enum SchemeDecision {
    /// Cached Http, `Never` mode, or an `http_only_mirrors` host.
    Http,
    /// Cached Https — a fixed scheme, not an upgrade attempt.
    Https,
    /// `Always` mode, uncached: HTTPS, non-revertible.
    AlwaysUpgrade,
    /// `Auto` mode, uncached: HTTPS, revertible (fall back to HTTP on failure).
    AutoUpgrade,
}

impl SchemeDecision {
    /// The concrete scheme to connect with; `None` means [`AutoUpgrade`](Self::AutoUpgrade)
    /// (try HTTPS, fall back to HTTP). Reproduces splice's `Option<Scheme>` view:
    /// `Https` and `AlwaysUpgrade` both map to `Some(Https)`.
    pub(crate) fn fixed_scheme(self) -> Option<Scheme> {
        match self {
            Self::Http => Some(Scheme::Http),
            Self::Https | Self::AlwaysUpgrade => Some(Scheme::Https),
            Self::AutoUpgrade => None,
        }
    }

    /// hyper: is this an HTTPS-upgrade attempt (set `https_upgrade_test`, bump
    /// `HTTPS_UPGRADE_ATTEMPTED`)? splice reads it for its own upgrade accounting.
    pub(crate) fn is_upgrade_attempt(self) -> bool {
        matches!(self, Self::AlwaysUpgrade | Self::AutoUpgrade)
    }

    /// hyper: may the upgrade revert to the original scheme on failure? (`Auto` only.)
    #[cfg(any(test, feature = "hyper"))]
    pub(crate) fn revertible(self) -> bool {
        matches!(self, Self::AutoUpgrade)
    }
}

/// The single scheme-decision truth table. Pure — no globals — so it is fully
/// unit-testable (both backends' inline resolvers call `global_config()` and are
/// not).
fn decide(cached: Option<Scheme>, is_http_only: bool, mode: HttpsUpgradeMode) -> SchemeDecision {
    if let Some(cached) = cached {
        return match cached {
            Scheme::Http => SchemeDecision::Http,
            Scheme::Https => SchemeDecision::Https,
        };
    }
    if is_http_only {
        return SchemeDecision::Http;
    }
    match mode {
        HttpsUpgradeMode::Never => SchemeDecision::Http,
        HttpsUpgradeMode::Always => SchemeDecision::AlwaysUpgrade,
        HttpsUpgradeMode::Auto => SchemeDecision::AutoUpgrade,
    }
}

/// The scheme currently cached for `key`, if any.
fn cached_scheme(key: SchemeKeyRef<'_>) -> Option<Scheme> {
    cache().read().get(&key).copied()
}

/// Resolve the upstream scheme for `key` from the cache and config — the single
/// entry point both backends use to decide HTTP vs HTTPS.
pub(crate) fn resolve(key: SchemeKeyRef<'_>, config: &Config) -> SchemeDecision {
    let cached = cached_scheme(key);
    // `decide` returns on `cached` before reading `is_http_only`; skip the
    // `http_only_mirrors` scan on a cache hit.
    let is_http_only =
        cached.is_none() && config.http_only_mirrors.iter().any(|m| m.permits(key.host));
    decide(cached, is_http_only, config.https_upgrade_mode)
}

/// Cache the scheme a successful upstream connection used. Vacant-only: an
/// existing entry is left untouched. Returns `true` if newly inserted, so the
/// caller can emit its own backend-flavored debug log.
pub(crate) fn record_success(key: SchemeKeyRef<'_>, scheme: Scheme) -> bool {
    let scheme_cache = cache();
    if scheme_cache.read().contains_key(&key) {
        return false;
    }
    if let EntryRef::Vacant(ventry) = scheme_cache.write().entry_ref(&key) {
        ventry.insert_entry_with_key(
            SchemeKey {
                host: key.host.to_owned(),
                port: key.port,
            },
            scheme,
        );
        true
    } else {
        false
    }
}

/// Evict any cached scheme for `key` after a terminal upstream failure, so the
/// next request re-resolves instead of retrying a dead scheme. Owns the
/// `SCHEME_CACHE_REMOVED` metric bump. Returns the removed scheme for logging.
pub(crate) fn record_failure(key: SchemeKeyRef<'_>) -> Option<Scheme> {
    let removed = cache().write().remove(&key);
    if removed.is_some() {
        metrics::SCHEME_CACHE_REMOVED.increment();
    }
    removed
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(host: &str) -> SchemeKeyRef<'_> {
        SchemeKeyRef { host, port: None }
    }

    #[test]
    fn key_from_authority_projects_host_and_port() {
        let auth = Authority::try_from("example.invalid:8080").expect("valid authority");
        let k = SchemeKeyRef::from(&auth);
        assert_eq!(k.host, "example.invalid");
        assert_eq!(k.port, Some(8080));

        let bare = Authority::try_from("example.invalid").expect("valid authority");
        assert_eq!(SchemeKeyRef::from(&bare).port, None);
    }

    #[test]
    fn scheme_from_uri_scheme_roundtrip() {
        assert_eq!(
            Scheme::from_uri_scheme(&http::uri::Scheme::HTTPS),
            Some(Scheme::Https)
        );
        assert_eq!(
            Scheme::from_uri_scheme(&http::uri::Scheme::HTTP),
            Some(Scheme::Http)
        );
        let ftp = http::uri::Scheme::try_from("ftp").expect("ftp is a valid scheme");
        assert_eq!(Scheme::from_uri_scheme(&ftp), None);
    }

    #[test]
    fn record_success_inserts_once_and_is_vacant_only() {
        let host = key("record-success.test.invalid");
        assert!(record_success(host, Scheme::Https));
        assert_eq!(cached_scheme(host), Some(Scheme::Https));
        // Vacant-only: an existing entry is never overwritten.
        assert!(!record_success(host, Scheme::Http));
        assert_eq!(cached_scheme(host), Some(Scheme::Https));
    }

    #[test]
    fn record_failure_evicts_and_returns_scheme() {
        let host = key("record-failure.test.invalid");
        record_success(host, Scheme::Https);
        assert_eq!(record_failure(host), Some(Scheme::Https));
        assert_eq!(cached_scheme(host), None);
        // Evicting an absent entry is a no-op returning None.
        assert_eq!(record_failure(host), None);
    }

    #[test]
    fn cached_scheme_wins_over_mode_and_http_only() {
        for mode in [
            HttpsUpgradeMode::Never,
            HttpsUpgradeMode::Auto,
            HttpsUpgradeMode::Always,
        ] {
            for http_only in [false, true] {
                assert_eq!(
                    decide(Some(Scheme::Http), http_only, mode),
                    SchemeDecision::Http
                );
                assert_eq!(
                    decide(Some(Scheme::Https), http_only, mode),
                    SchemeDecision::Https
                );
            }
        }
    }

    #[test]
    fn uncached_http_only_is_http_regardless_of_mode() {
        for mode in [
            HttpsUpgradeMode::Never,
            HttpsUpgradeMode::Auto,
            HttpsUpgradeMode::Always,
        ] {
            assert_eq!(decide(None, true, mode), SchemeDecision::Http);
        }
    }

    #[test]
    fn uncached_never_is_http() {
        assert_eq!(
            decide(None, false, HttpsUpgradeMode::Never),
            SchemeDecision::Http
        );
    }

    #[test]
    fn uncached_always_is_always_upgrade() {
        assert_eq!(
            decide(None, false, HttpsUpgradeMode::Always),
            SchemeDecision::AlwaysUpgrade
        );
    }

    #[test]
    fn uncached_auto_is_auto_upgrade() {
        assert_eq!(
            decide(None, false, HttpsUpgradeMode::Auto),
            SchemeDecision::AutoUpgrade
        );
    }

    #[test]
    fn fixed_scheme_projection_matches_splice_option_view() {
        assert_eq!(SchemeDecision::Http.fixed_scheme(), Some(Scheme::Http));
        assert_eq!(SchemeDecision::Https.fixed_scheme(), Some(Scheme::Https));
        assert_eq!(
            SchemeDecision::AlwaysUpgrade.fixed_scheme(),
            Some(Scheme::Https)
        );
        assert_eq!(SchemeDecision::AutoUpgrade.fixed_scheme(), None);
    }

    #[test]
    fn upgrade_attempt_and_revertible_flags() {
        assert!(!SchemeDecision::Http.is_upgrade_attempt());
        assert!(!SchemeDecision::Https.is_upgrade_attempt());
        assert!(SchemeDecision::AlwaysUpgrade.is_upgrade_attempt());
        assert!(SchemeDecision::AutoUpgrade.is_upgrade_attempt());

        assert!(!SchemeDecision::AlwaysUpgrade.revertible());
        assert!(SchemeDecision::AutoUpgrade.revertible());
    }
}
