//! Process-wide upstream-scheme cache and the shared HTTP-vs-HTTPS decision
//! logic used by both the hyper and splice backends.
//!
//! The retry/revert machinery (hyper `inner_loop`) and the connect-with-fallback
//! flow (splice `connect_upstream`) stay backend-specific — this module owns the
//! scheme types, the decision (`resolve`/`decide`), and the cache read/insert/evict
//! (`record_success`/`record_failure`).
//!
//! A learned HTTPS scheme is kept until a terminal failure evicts it; a
//! rejected certificate never does, as the entry is what makes that rejection
//! terminal under `Auto` ([`https_verified_before`]). A learned
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

use crate::config::{Config, DomainName, HttpsUpgradeMode};
use crate::deb_mirror::Mirror;
use crate::metrics;
use crate::uri_authority;

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

/// The authority's host keys the cache in the bare canonical text a
/// `Mirror` host carries: an IPv6 literal loses the brackets its URI
/// spelling needs (RFC 3986 §3.2.2) by slicing, so the lookup stays
/// allocation-free. The authority must already be canonical (hyper's
/// `request_with_retry` passes it through [`canonical_authority`] first), or
/// the two backends would key one host under two spellings.
impl<'a> From<&'a Authority> for SchemeKeyRef<'a> {
    fn from(auth: &'a Authority) -> Self {
        debug_assert!(
            canonical_authority(auth).is_none(),
            "scheme-cache key from the non-canonical authority `{auth}`"
        );
        let host = auth.host();
        let host = host
            .strip_prefix('[')
            .and_then(|inner| inner.strip_suffix(']'))
            .unwrap_or(host);
        Self {
            host,
            port: uri_authority::port(auth)
                .expect("validated upstream authority")
                .map(NonZero::get),
        }
    }
}

/// The canonical spelling of `auth`, or `None` when it already is canonical
/// (or its host or port is invalid, which the callers' own gates
/// reject): a DNS name lowercased, an IPv6 literal in its RFC 5952 text
/// (`[0:0::1]` and `[::1]` are one host), the port kept as its number
/// (`:080` is `:80`).
///
/// Every host the proxy keys state on is the canonical [`DomainName`] text.
/// A client URI or a redirect `Location` may spell the same host otherwise,
/// and hyper's upstream request would then key the scheme cache, and match
/// `http_only_mirrors`, under a name no `Mirror` carries.
#[must_use]
pub(crate) fn canonical_authority(auth: &Authority) -> Option<Authority> {
    let port = uri_authority::port(auth).ok()?;
    let host = auth.host();
    // Fast path, no allocation: a lowercase DNS name or an IPv4 address
    // (whose parser admits only the canonical dotted quad) is canonical.
    if !host.starts_with('[') && !host.bytes().any(|b| b.is_ascii_uppercase()) {
        return None;
    }
    let canonical = DomainName::new(host).ok()?;
    let rendered = canonical.format_authority(port);
    if rendered == auth.as_str() {
        return None;
    }
    Authority::try_from(rendered.as_ref()).ok()
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

/// Whether HTTPS to `key` has verified before: a remembered HTTPS scheme.
/// Decides what a rejected certificate means under `Auto` (trust on first
/// use): for a host never reached over verified TLS, likely a mirror answering
/// on 443 with another host's certificate, so the probe falls back to HTTP;
/// for one that has been, what an interceptor presents, so it is terminal.
#[must_use]
pub(crate) fn https_verified_before(key: SchemeKeyRef<'_>) -> bool {
    cached_scheme_at(key, Instant::now()) == Some(Scheme::Https)
}

/// Why a rejected certificate was terminal instead of falling back to plain
/// HTTP, as both backends word it in their operator line: `mode` is the
/// configured `https_upgrade_mode`. Every other mode got there through a
/// remembered HTTPS success ([`https_verified_before`]).
#[must_use]
pub(crate) const fn no_fallback_reason(mode: HttpsUpgradeMode) -> &'static str {
    match mode {
        HttpsUpgradeMode::Always => "`https_upgrade_mode` is `Always`",
        HttpsUpgradeMode::Auto | HttpsUpgradeMode::Never => {
            "an earlier HTTPS connection to it verified"
        }
    }
}

/// Resolve the upstream scheme for `key` from the cache and config — the single
/// entry point both backends use to decide HTTP vs HTTPS.
pub(crate) fn resolve(key: SchemeKeyRef<'_>, config: &Config) -> SchemeDecision {
    let cached = cached_scheme_at(key, Instant::now());
    // `decide` returns on `cached` before reading `is_http_only`; skip the
    // `http_only_mirrors` scan on a cache hit.
    let is_http_only = cached.is_none() && is_http_only(key, config);
    decide(cached, is_http_only, config.https_upgrade_mode)
}

/// A live cache entry, as the dashboard reads it: the scheme and, for a
/// learned HTTP scheme, how long until it expires and `Auto` probes HTTPS
/// again.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct LiveScheme {
    pub(crate) scheme: Scheme,
    /// `Some` for an HTTP entry only; HTTPS entries do not age.
    pub(crate) expires_in: Option<coarsetime::Duration>,
}

/// The live entry for `key`, `None` without one (never learned, evicted
/// after a terminal failure, or an expired HTTP entry).
#[must_use]
pub(crate) fn live_entry(key: SchemeKeyRef<'_>) -> Option<LiveScheme> {
    live_entry_at(key, Instant::now())
}

/// [`live_entry`] at the given clock reading.
fn live_entry_at(key: SchemeKeyRef<'_>, now: Instant) -> Option<LiveScheme> {
    let entry = *cache().read().get(&key)?;
    let scheme = entry.live_at(now)?;
    let expires_in = match scheme {
        Scheme::Https => None,
        Scheme::Http => Some(HTTP_SCHEME_TTL.saturating_sub(now.duration_since(entry.learned))),
    };
    Some(LiveScheme { scheme, expires_in })
}

/// The scheme a mirror is dialled with now and why, for the dashboard's
/// Mirrors table. Each points the operator at one config option, or at the
/// mirror; only [`Self::HttpFallback`] is a bad sign.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SchemeVerdict {
    /// Plain HTTP because `http_only_mirrors` lists the host.
    HttpOnlyListed,
    /// Plain HTTP because `https_upgrade_mode` is `Never`.
    HttpNever,
    /// HTTPS because `https_upgrade_mode` is `Always` (no fallback).
    HttpsForced,
    /// HTTPS, learned by an `Auto` upgrade probe that succeeded.
    HttpsUpgraded,
    /// Plain HTTP under `Auto` after a failed HTTPS probe: the host has no
    /// TLS, or presented a certificate that did not verify. HTTPS is probed
    /// again once the entry expires, `reprobe_in` from now.
    HttpFallback { reprobe_in: coarsetime::Duration },
    /// `Auto` with no live entry: not dialled since start (or since the entry
    /// was evicted or expired); the next request probes HTTPS.
    Undecided,
}

impl SchemeVerdict {
    /// The scheme the next request uses, `None` while undecided.
    #[must_use]
    pub(crate) const fn scheme(self) -> Option<Scheme> {
        match self {
            Self::HttpOnlyListed | Self::HttpNever | Self::HttpFallback { reprobe_in: _ } => {
                Some(Scheme::Http)
            }
            Self::HttpsForced | Self::HttpsUpgraded => Some(Scheme::Https),
            Self::Undecided => None,
        }
    }
}

/// The verdict for a host from the configuration and its live cache entry.
/// Pure, like [`decide`], but the configured HTTP cases come first where
/// `decide` puts a live entry first: the two agree because a live entry
/// never contradicts them (no upgrade is attempted for such a host, and no
/// scheme is recorded for one the mode fixes), and naming the option is
/// what the dashboard needs. Then the mode.
#[must_use]
fn verdict(mode: HttpsUpgradeMode, is_http_only: bool, live: Option<LiveScheme>) -> SchemeVerdict {
    if is_http_only {
        return SchemeVerdict::HttpOnlyListed;
    }
    match mode {
        HttpsUpgradeMode::Never => SchemeVerdict::HttpNever,
        HttpsUpgradeMode::Always => SchemeVerdict::HttpsForced,
        HttpsUpgradeMode::Auto => match live {
            Some(LiveScheme {
                scheme: Scheme::Https,
                expires_in: _,
            }) => SchemeVerdict::HttpsUpgraded,
            Some(LiveScheme {
                scheme: Scheme::Http,
                expires_in,
            }) => SchemeVerdict::HttpFallback {
                reprobe_in: expires_in.unwrap_or(coarsetime::Duration::from_ticks(0)),
            },
            None => SchemeVerdict::Undecided,
        },
    }
}

/// [`verdict`] for `key` from the global cache and `config`.
#[must_use]
pub(crate) fn verdict_for(key: SchemeKeyRef<'_>, config: &Config) -> SchemeVerdict {
    verdict(
        config.https_upgrade_mode,
        is_http_only(key, config),
        live_entry(key),
    )
}

/// Whether `http_only_mirrors` lists the host of `key`. The key carries the
/// canonical text, which parses back to the host it was rendered from; a
/// text that does not parse names no host any entry could list.
fn is_http_only(key: SchemeKeyRef<'_>, config: &Config) -> bool {
    !config.http_only_mirrors.is_empty()
        && DomainName::new(key.host)
            .is_ok_and(|host| config.http_only_mirrors.iter().any(|m| m.permits(&host)))
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
    use crate::config::ClientHost;
    use crate::deb_mirror::MirrorKind;

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

    /// hyper keys on the request authority, splice on the `Mirror`: an IPv6
    /// mirror must be one entry in both, keyed on the bare canonical text.
    #[test]
    fn key_from_an_ipv6_authority_matches_the_mirror_key() {
        let auth = Authority::try_from("[2001:db8::1]:8080").expect("valid authority");
        let from_auth = SchemeKeyRef::from(&auth);
        let mirror = Mirror::new(
            ClientHost::new("2001:db8::1").expect("valid host"),
            NonZero::new(8080),
            "debian".to_owned(),
            MirrorKind::Structured,
        );
        let from_mirror = SchemeKeyRef::from(&mirror);
        let SchemeKeyRef { host, port } = from_auth;
        assert_eq!((host, port), (from_mirror.host, from_mirror.port));
        assert_eq!(host, "2001:db8::1");

        assert!(record_success(from_mirror, Scheme::Http));
        assert_eq!(
            live_entry(from_auth).map(|live| live.scheme),
            Some(Scheme::Http),
            "an entry splice learned is the one hyper reads"
        );
    }

    #[test]
    fn canonical_authority_folds_every_spelling_of_a_host() {
        for (raw, canonical) in [
            ("DEB.Debian.ORG", "deb.debian.org"),
            ("Deb.debian.org:8080", "deb.debian.org:8080"),
            ("[2001:DB8::1]", "[2001:db8::1]"),
            ("[2001:db8:0:0:0:0:0:1]:3142", "[2001:db8::1]:3142"),
            ("[0:0::1]", "[::1]"),
            ("[::ffff:192.0.2.1]:8080", "192.0.2.1:8080"),
        ] {
            let auth = Authority::try_from(raw).expect("valid authority");
            let folded = canonical_authority(&auth).expect("non-canonical input");
            assert_eq!(folded.as_str(), canonical, "{raw}");
            assert_eq!(
                canonical_authority(&folded),
                None,
                "{canonical} is a fixpoint"
            );
        }
        for already in [
            "deb.debian.org",
            "deb.debian.org:80",
            "192.0.2.1:8080",
            "[::1]",
            "[2001:db8::1]:8080",
            // Port 0 is left alone rather than dropped to the default port.
            "[0:0::1]:0",
            // Invalid explicit ports must never be rewritten to no port.
            "[0:0::1]:65536",
            "[::ffff:192.0.2.1]:nonsense",
            "DEB.Debian.ORG:65536",
        ] {
            let auth = Authority::try_from(already).expect("valid authority");
            assert_eq!(canonical_authority(&auth), None, "{already}");
        }
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
    fn https_verified_before_only_for_a_remembered_https_scheme() {
        let https = key("verified-https.test.invalid");
        let http = key("verified-http.test.invalid");
        assert!(!https_verified_before(https));
        assert!(record_success(https, Scheme::Https));
        assert!(record_success(http, Scheme::Http));
        assert!(https_verified_before(https));
        assert!(
            !https_verified_before(http),
            "an HTTP fallback proves nothing"
        );
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

    /// A live HTTP entry reports the time until Auto probes HTTPS again; an
    /// HTTPS one does not age.
    #[test]
    fn a_live_entry_carries_its_remaining_lifetime() {
        let http = key("live-http.test.invalid");
        let https = key("live-https.test.invalid");
        let t0 = Instant::now();
        let ten_min = coarsetime::Duration::from_secs(600);
        assert_eq!(live_entry_at(http, t0), None);
        assert!(record_success_at(http, Scheme::Http, t0));
        assert!(record_success_at(https, Scheme::Https, t0));
        assert_eq!(
            live_entry_at(http, t0 + ten_min),
            Some(LiveScheme {
                scheme: Scheme::Http,
                expires_in: Some(HTTP_SCHEME_TTL - ten_min),
            })
        );
        assert_eq!(live_entry_at(http, t0 + HTTP_SCHEME_TTL), None, "expired");
        assert_eq!(
            live_entry_at(https, t0 + HTTP_SCHEME_TTL),
            Some(LiveScheme {
                scheme: Scheme::Https,
                expires_in: None,
            })
        );
    }

    #[test]
    fn the_verdict_names_why_a_mirror_is_dialled_as_it_is() {
        let https = Some(LiveScheme {
            scheme: Scheme::Https,
            expires_in: None,
        });
        let reprobe_in = coarsetime::Duration::from_secs(1200);
        let http = Some(LiveScheme {
            scheme: Scheme::Http,
            expires_in: Some(reprobe_in),
        });
        for mode in [
            HttpsUpgradeMode::Never,
            HttpsUpgradeMode::Auto,
            HttpsUpgradeMode::Always,
        ] {
            for live in [None, https, http] {
                assert_eq!(
                    verdict(mode, true, live),
                    SchemeVerdict::HttpOnlyListed,
                    "configured HTTP wins: {mode:?} {live:?}"
                );
            }
            assert_eq!(
                verdict(mode, false, None).scheme().is_none(),
                mode == HttpsUpgradeMode::Auto
            );
        }
        assert_eq!(
            verdict(HttpsUpgradeMode::Never, false, http),
            SchemeVerdict::HttpNever
        );
        assert_eq!(
            verdict(HttpsUpgradeMode::Always, false, None),
            SchemeVerdict::HttpsForced
        );
        assert_eq!(
            verdict(HttpsUpgradeMode::Auto, false, https),
            SchemeVerdict::HttpsUpgraded
        );
        assert_eq!(
            verdict(HttpsUpgradeMode::Auto, false, http),
            SchemeVerdict::HttpFallback { reprobe_in }
        );
        assert_eq!(
            verdict(HttpsUpgradeMode::Auto, false, None),
            SchemeVerdict::Undecided
        );
    }

    /// The table looks entries up by the row's own port: an explicit `:80`
    /// is a key of its own, as it is for the backends that record it.
    #[test]
    fn an_explicit_default_port_is_its_own_entry() {
        let bare = SchemeKeyRef {
            host: "explicit-port.test.invalid",
            port: None,
        };
        let explicit = SchemeKeyRef {
            port: Some(80),
            ..bare
        };
        assert!(record_success(explicit, Scheme::Http));
        assert_eq!(live_entry(bare), None);
        assert_eq!(
            live_entry(explicit).map(|live| live.scheme),
            Some(Scheme::Http)
        );
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
