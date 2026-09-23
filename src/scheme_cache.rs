//! Process-wide upstream-scheme cache and the shared HTTP-vs-HTTPS decision
//! logic used by both the hyper and splice backends.
//!
//! The retry/revert machinery (hyper `inner_loop`) and the connect-with-fallback
//! flow (splice `connect_upstream`) stay backend-specific — this module owns the
//! scheme types, the decision (`resolve`/`decide`), and the cache read/insert/evict
//! (`record_success`/`record_failure`).
//!
//! A learned HTTPS scheme is kept until a terminal failure evicts it. A learned
//! HTTP scheme only lives for [`HTTP_SCHEME_TTL`]: under `Auto` it records a
//! failed upgrade probe, and a host that could not do TLS once (a transient
//! outage, an on-path attacker blocking the handshake) must not be dialled in
//! cleartext for the rest of the process lifetime.

use std::fmt::Display;
use std::num::NonZero;
use std::sync::OnceLock;

use coarsetime::Instant;
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

/// Owned `(host, port)` key for the scheme cache.
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

/// How long a learned HTTP scheme is remembered before the host is treated
/// as uncached again, so `Auto` mode probes HTTPS anew. Learned HTTPS is not
/// aged.
pub(crate) const HTTP_SCHEME_TTL: coarsetime::Duration = coarsetime::Duration::from_secs(60 * 60);

/// A cache entry: the scheme and when it was learned.
#[derive(Clone, Copy, Debug)]
struct CachedScheme {
    scheme: Scheme,
    learned: Instant,
}

impl CachedScheme {
    /// The scheme, unless it is an HTTP entry older than [`HTTP_SCHEME_TTL`]
    /// at `now`.
    fn live_at(self, now: Instant) -> Option<Scheme> {
        let Self { scheme, learned } = self;
        match scheme {
            Scheme::Https => Some(scheme),
            Scheme::Http => (now.duration_since(learned) < HTTP_SCHEME_TTL).then_some(scheme),
        }
    }
}

/// Process-wide cache of the scheme last known good for each upstream host.
/// Module-private: reach it only through [`cache`] and the functions below.
static SCHEME_CACHE: OnceLock<RwLock<HashMap<SchemeKey, CachedScheme>>> = OnceLock::new();

fn cache() -> &'static RwLock<HashMap<SchemeKey, CachedScheme>> {
    SCHEME_CACHE.get_or_init(|| RwLock::new(HashMap::new()))
}

/// Debug-format the current cache contents, for the startup warm-up trace.
#[cfg(feature = "hyper")]
pub(crate) fn debug_contents() -> String {
    format!("{:?}", *cache().read())
}

/// The scheme decision for one upstream request, richer than a bare `Scheme` so
/// a backend can tell an HTTPS *upgrade attempt* (which bumps
/// `HTTPS_UPGRADE_ATTEMPTED` and may revert) apart from a fixed HTTPS scheme,
/// while splice collapses it back to its `Option<Scheme>` view via
/// [`fixed_scheme`].
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

    /// Is this an HTTPS-upgrade attempt rather than a fixed scheme?  splice
    /// reads it for its upgrade accounting; hyper folds the same distinction
    /// into its own `UpgradeProbe`.
    #[cfg(any(test, feature = "splice"))]
    pub(crate) fn is_upgrade_attempt(self) -> bool {
        matches!(self, Self::AlwaysUpgrade | Self::AutoUpgrade)
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

/// The scheme cached for `key` at `now`, if a live one. Taking the clock as
/// a parameter keeps the TTL testable without sleeping.
fn cached_scheme_at(key: SchemeKeyRef<'_>, now: Instant) -> Option<Scheme> {
    cache()
        .read()
        .get(&key)
        .and_then(|entry| entry.live_at(now))
}

/// Resolve the upstream scheme for `key` from the cache and config — the single
/// entry point both backends use to decide HTTP vs HTTPS.
pub(crate) fn resolve(key: SchemeKeyRef<'_>, config: &Config) -> SchemeDecision {
    let cached = cached_scheme_at(key, Instant::now());
    // `decide` returns on `cached` before reading `is_http_only`; skip the
    // `http_only_mirrors` scan on a cache hit.
    let is_http_only =
        cached.is_none() && config.http_only_mirrors.iter().any(|m| m.permits(key.host));
    decide(cached, is_http_only, config.https_upgrade_mode)
}

/// Cache the scheme a successful upstream connection used. Vacant-only: a
/// live entry is left untouched, an expired HTTP entry is replaced (and dated
/// afresh). Returns `true` if newly inserted, so the caller can emit its own
/// backend-flavored debug log.
pub(crate) fn record_success(key: SchemeKeyRef<'_>, scheme: Scheme) -> bool {
    record_success_at(key, scheme, Instant::now())
}

/// [`record_success`] at the given clock reading.
fn record_success_at(key: SchemeKeyRef<'_>, scheme: Scheme, now: Instant) -> bool {
    if cached_scheme_at(key, now).is_some() {
        return false;
    }
    let entry = CachedScheme {
        scheme,
        learned: now,
    };
    match cache().write().entry_ref(&key) {
        EntryRef::Occupied(mut occupied) => {
            // Re-checked under the write lock: a racing request may have
            // learned a scheme since the read above.
            if occupied.get().live_at(now).is_some() {
                return false;
            }
            *occupied.get_mut() = entry;
        }
        EntryRef::Vacant(ventry) => {
            ventry.insert_entry_with_key(
                SchemeKey {
                    host: key.host.to_owned(),
                    port: key.port,
                },
                entry,
            );
        }
    }
    true
}

/// Evict any cached scheme for `key` after a terminal upstream failure, so the
/// next request re-resolves instead of retrying a dead scheme. Owns the
/// `SCHEME_CACHE_REMOVED` metric bump. Returns the removed scheme for logging;
/// an expired entry is dropped silently, as it no longer decided anything.
pub(crate) fn record_failure(key: SchemeKeyRef<'_>) -> Option<Scheme> {
    record_failure_at(key, Instant::now())
}

/// [`record_failure`] at the given clock reading.
fn record_failure_at(key: SchemeKeyRef<'_>, now: Instant) -> Option<Scheme> {
    let removed = cache()
        .write()
        .remove(&key)
        .and_then(|entry| entry.live_at(now));
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
        assert_eq!(cached_scheme_at(host, Instant::now()), Some(Scheme::Https));
        // Vacant-only: an existing entry is never overwritten.
        assert!(!record_success(host, Scheme::Http));
        assert_eq!(cached_scheme_at(host, Instant::now()), Some(Scheme::Https));
    }

    #[test]
    fn record_failure_evicts_and_returns_scheme() {
        let host = key("record-failure.test.invalid");
        record_success(host, Scheme::Https);
        assert_eq!(record_failure(host), Some(Scheme::Https));
        assert_eq!(cached_scheme_at(host, Instant::now()), None);
        // Evicting an absent entry is a no-op returning None.
        assert_eq!(record_failure(host), None);
    }

    /// An Auto-mode HTTP fallback is only remembered for `HTTP_SCHEME_TTL`;
    /// then the host is treated as uncached again, so Auto probes HTTPS.
    #[test]
    fn http_entry_expires_after_ttl() {
        let host = key("http-ttl.test.invalid");
        let t0 = Instant::now();
        let second = coarsetime::Duration::from_secs(1);
        assert!(record_success_at(host, Scheme::Http, t0));
        assert_eq!(
            cached_scheme_at(host, t0 + HTTP_SCHEME_TTL - second),
            Some(Scheme::Http)
        );
        let expired = t0 + HTTP_SCHEME_TTL;
        assert_eq!(cached_scheme_at(host, expired), None);
        assert_eq!(
            decide(
                cached_scheme_at(host, expired),
                false,
                HttpsUpgradeMode::Auto
            ),
            SchemeDecision::AutoUpgrade,
            "an expired HTTP fallback re-probes HTTPS"
        );
    }

    #[test]
    fn https_entry_does_not_expire() {
        let host = key("https-no-ttl.test.invalid");
        let t0 = Instant::now();
        assert!(record_success_at(host, Scheme::Https, t0));
        assert_eq!(
            cached_scheme_at(host, t0 + HTTP_SCHEME_TTL + HTTP_SCHEME_TTL),
            Some(Scheme::Https)
        );
    }

    /// Vacant-only applies to live entries: an expired HTTP entry is
    /// replaced by the outcome of the next probe, and dated afresh.
    #[test]
    fn expired_http_entry_is_replaced() {
        let host = key("http-replace.test.invalid");
        let t0 = Instant::now();
        let second = coarsetime::Duration::from_secs(1);
        assert!(record_success_at(host, Scheme::Http, t0));
        assert!(
            !record_success_at(host, Scheme::Https, t0 + second),
            "a live entry is never overwritten"
        );
        let expired = t0 + HTTP_SCHEME_TTL;
        assert!(record_success_at(host, Scheme::Http, expired));
        assert_eq!(
            cached_scheme_at(host, expired + HTTP_SCHEME_TTL - second),
            Some(Scheme::Http),
            "the re-learned fallback runs its own TTL"
        );
        let expired_again = expired + HTTP_SCHEME_TTL;
        assert!(record_success_at(host, Scheme::Https, expired_again));
        assert_eq!(cached_scheme_at(host, expired_again), Some(Scheme::Https));
    }

    /// Evicting an expired entry reports nothing: it no longer decided how
    /// the host was dialled.
    #[test]
    fn record_failure_ignores_expired_entry() {
        let host = key("http-evict-expired.test.invalid");
        let t0 = Instant::now();
        assert!(record_success_at(host, Scheme::Http, t0));
        assert_eq!(record_failure_at(host, t0 + HTTP_SCHEME_TTL), None);
        assert_eq!(cached_scheme_at(host, t0), None, "the entry is gone");
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
    fn upgrade_attempt_flag() {
        assert!(!SchemeDecision::Http.is_upgrade_attempt());
        assert!(!SchemeDecision::Https.is_upgrade_attempt());
        assert!(SchemeDecision::AlwaysUpgrade.is_upgrade_attempt());
        assert!(SchemeDecision::AutoUpgrade.is_upgrade_attempt());
    }
}
