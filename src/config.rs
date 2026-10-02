//! Daemon configuration: TOML parsing, defaults, CLI overrides and
//! `validate()`.
//!
//! Adding an option: the serde field (struct-level `#[serde(default)]`
//! supplies missing keys from `Config::default()`, so only a
//! `deserialize_with` is ever needed on the field) + its value in the
//! `impl Default for Config` block + a `validate()` warning when it has no
//! effect + a commented entry in `debian/apt-cacher-rs.conf`. The man page
//! and README document CLI flags only.
//!
//! "Set but has no effect" warnings must test `self.is_set("key")` (the
//! key's structural presence in the TOML document), never compare the value
//! against its default: an operator who writes the default value explicitly
//! still gets the warning.
//!
//! Removing an option: its key goes into [`REMOVED_OPTIONS`] instead of
//! vanishing, so `deny_unknown_fields` does not turn an old configuration
//! file into a startup failure; `validate()` warns that it is ignored.
//!
//! A CLI flag that *overrides* a config field instead: a `Cli` field in
//! `main.rs` + a `Config::load` parameter applied on top of the parsed TOML
//! **before** `validate()` + man page + README, and no
//! `debian/apt-cacher-rs.conf` entry. Fallible flag values parse via
//! `FromStr<Err = String>` on a type in this module (see `BindOverride`);
//! infallible ones via `From<String>` (see `LogDestination`).

use std::{
    borrow::Cow,
    cmp::Ordering,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    num::NonZero,
    path::{Path, PathBuf},
    str::FromStr,
    time::Duration,
};

use hashbrown::HashSet;
use http::StatusCode;
use ipnet::IpNet;
use serde::{Deserialize, Deserializer};
use tracing::level_filters::LevelFilter;

use crate::client_counter;
use crate::humanfmt::HumanFmt;
use crate::limits::VOLATILE_UNKNOWN_CONTENT_LENGTH_UPPER;
use crate::nonzero;

/// Failure while loading or validating the configuration.
///
/// `Display` renders this error only; the underlying cause hangs off
/// [`std::error::Error::source`], so log it via [`crate::error::ErrorReport`].
#[derive(Debug, thiserror::Error)]
pub(crate) enum ConfigError {
    #[error("Failed to read file `{}`", path.display())]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("Failed to parse configuration")]
    Parse(#[source] toml::de::Error),
    /// A cross-field validation rule rejected the configuration.
    #[error("{0}")]
    Invalid(String),
}

/// `return`s a [`ConfigError::Invalid`] built from the given format arguments.
macro_rules! invalid {
    ($($arg:tt)*) => {
        return Err(ConfigError::Invalid(format!($($arg)*)))
    };
}

pub(crate) const DEFAULT_CONFIGURATION_PATH: &str = "/etc/apt-cacher-rs/apt-cacher-rs.conf";

/// Top-level keys of options that no longer exist. [`Config::from_toml`]
/// drops them before deserializing (whatever their value), and `validate()`
/// warns about each one set.
///
/// - `mmap_threshold`: the memory-mapped serve path was removed, because a
///   mapped cache file truncated behind the daemon's back (or a media error)
///   raises `SIGBUS` and kills the whole process.
const REMOVED_OPTIONS: &[&str] = &["mmap_threshold"];

/// Default of [`Config::rate_check_timeframe`]; a named const (not a field of
/// `Config::default()`) because `ringbuffer.rs` pins its inline capacity to it
/// in a `static_assert!`.
pub(crate) const DEFAULT_RATE_CHECK_TIMEFRAME: NonZero<usize> = nonzero!(30);

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
pub(crate) enum HttpsUpgradeMode {
    /// Try HTTPS first, fall back to HTTP. A rejected certificate falls back
    /// too, unless HTTPS to the host verified before in this process (trust
    /// on first use, `scheme_cache::https_verified_before`): then it is
    /// terminal.
    Auto,
    /// HTTPS only; a rejected certificate is terminal.
    Always,
    /// Plain HTTP only.
    Never,
}

/// Why a host string is no [`DomainName`] (or no [`ConfigDomainName`]).
///
/// `Display` is the reason clause every rejection interpolates: the
/// request edge's 400 line, the configuration error and the database row
/// warning.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub(crate) enum HostError {
    /// Neither a DNS name nor an IP address (nor, in the configuration, a
    /// `*.` wildcard).
    #[error("not a valid DNS name or IP address")]
    Invalid,
    /// An IPv6 address with a zone identifier (`fe80::1%eth0`, in a URI
    /// `[fe80::1%25eth0]`). A zone names an interface of the host that
    /// reads it, so it cannot name a mirror every client shares.
    #[error("IPv6 zone identifiers are not supported")]
    ZoneId,
    /// A host followed by a port (`[2001:db8::1]:8080`, `example.org:80`),
    /// where only a host belongs.
    #[error("a host must not carry a port")]
    Port,
    /// A DNS name whose last label is numeric (`1.2.3`, `0x7f.1`,
    /// `2130706433`): resolvers read it as an IPv4 address, so it would be
    /// a second name for an address host.
    #[error("a DNS name must not end in a numeric label")]
    NumericName,
}

#[derive(Debug, PartialEq, Eq)]
enum ConfigDomainNameInner {
    /// One host, parsed by [`DomainName::new`].
    Exact(DomainName),
    /// The suffix after `*`, including its leading dot, lowercase.
    Wildcard(String),
}

/// An allow-list *pattern*, which may be a wildcard and so has no useful
/// ordering: the lists it populates (`allowed_mirrors`, `http_only_mirrors`)
/// are always scanned with [`Self::permits`], never sorted or searched.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ConfigDomainName(ConfigDomainNameInner);

impl ConfigDomainName {
    /// A `*.`-prefixed wildcard, or any host [`DomainName::new`] accepts
    /// (an IPv6 address bare or bracketed), so an entry and the host a
    /// request names are parsed by one parser.
    pub(crate) fn new(domain: impl AsRef<str>) -> Result<Self, HostError> {
        let domain = domain.as_ref();

        // DNS names are case-insensitive: normalise so `DEB.debian.org` and
        // `deb.debian.org` are one allow-list entry, one cache tree and one
        // mirror row.
        if let Some(suffix) = domain.strip_prefix('*') {
            if !is_valid_wildcard(domain) {
                return Err(HostError::Invalid);
            }
            return Ok(Self(ConfigDomainNameInner::Wildcard(
                suffix.to_ascii_lowercase(),
            )));
        }

        DomainName::new(domain).map(|host| Self(ConfigDomainNameInner::Exact(host)))
    }

    /// The one host an exact entry names; `None` for a wildcard.
    #[must_use]
    #[inline]
    pub(crate) const fn host(&self) -> Option<&DomainName> {
        match self {
            Self(ConfigDomainNameInner::Exact(host)) => Some(host),
            Self(ConfigDomainNameInner::Wildcard(_)) => None,
        }
    }

    /// Whether the entry admits `domain`. Typed, so an entry and a host
    /// compare as the one canonical value each spelling parses to. A
    /// wildcard admits DNS names only: its suffix is DNS labels, which an
    /// address never ends in.
    #[must_use]
    pub(crate) fn permits(&self, domain: &DomainName) -> bool {
        match self {
            Self(ConfigDomainNameInner::Wildcard(suffix)) => {
                domain.is_dns() && domain.as_str().ends_with(suffix.as_str())
            }
            Self(ConfigDomainNameInner::Exact(host)) => host == domain,
        }
    }
}

impl<'de> Deserialize<'de> for ConfigDomainName {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::Error as _;
        let s: String = Deserialize::deserialize(deserializer)?;

        Self::new(&s).map_err(|err| {
            D::Error::custom(format!(
                "Invalid configuration domain `{}`: {err}",
                s.escape_debug()
            ))
        })
    }
}

/// Inner strings are `Arc<str>`: `DomainName` rides inside
/// `ClientHost`/`CacheHost`/`Mirror`, which are cloned into
/// active-download keys, metadata-cache keys, DB commands, and the
/// permitted-host cache on hot paths — a refcount bump instead of a
/// String allocation each time.  `Arc<str>` hashes/compares by content,
/// so map-key semantics are unchanged.
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
enum DomainNameInner {
    Dns(std::sync::Arc<str>),
    Ipv4(std::sync::Arc<str>, Ipv4Addr),
    Ipv6(std::sync::Arc<str>, Ipv6Addr),
}

/// A validated mirror host: a DNS name, an IPv4 or an IPv6 address.
///
/// The one parser for every host the proxy reads - a request's authority,
/// a CONNECT target, a redirect `Location`, the configuration and a
/// database row - so each spelling of a host maps to one value. The text it
/// keeps ([`Self::as_str`]) is canonical and bare: a DNS name lowercased, an
/// IPv6 address in its RFC 5952 form without brackets. That text keys every
/// store and table; [`Self::format_authority`] is its URI form, for URIs,
/// the `Host` header, cache directory names and log lines.
/// `DomainName::new(h.as_str()) == Ok(h)` for every value.
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub(crate) struct DomainName(DomainNameInner);

impl DomainName {
    /// Parse a host. An IPv6 address may be bare (`2001:db8::1`, the
    /// configuration's form) or bracketed (`[2001:db8::1]`, the URI form);
    /// a zone identifier or a trailing port is rejected with its own
    /// [`HostError`].
    pub(crate) fn new(domain: impl AsRef<str>) -> Result<Self, HostError> {
        let domain = domain.as_ref();

        if let Some(rest) = domain.strip_prefix('[') {
            let Some((inner, suffix)) = rest.split_once(']') else {
                return Err(HostError::Invalid);
            };
            if !suffix.is_empty() {
                return Err(if suffix.strip_prefix(':').is_some_and(is_port) {
                    HostError::Port
                } else {
                    HostError::Invalid
                });
            }
            return Self::ipv6(inner);
        }

        if domain.contains(':') {
            return Self::ipv6(domain).map_err(|err| match domain.rsplit_once(':') {
                // `example.org:80`, `192.0.2.1:80`: one colon, digits after it.
                Some((host, port)) if !host.contains(':') && is_port(port) => HostError::Port,
                Some(_) | None => err,
            });
        }

        if let Ok(addr) = domain.parse::<Ipv4Addr>() {
            return Ok(Self(DomainNameInner::Ipv4(addr.to_string().into(), addr)));
        }

        // At this point we've already proven there's no `:` and the string
        // is not a valid IPv4 address, so skip those branches in the
        // validator.
        if !is_valid_dns_label_string(domain) {
            return Err(HostError::Invalid);
        }
        if ends_in_a_number(domain) {
            return Err(HostError::NumericName);
        }
        // DNS names are case-insensitive: one cache tree, mirror row and
        // registry scope per host, whatever case the client typed.
        Ok(Self(DomainNameInner::Dns(
            domain.to_ascii_lowercase().into(),
        )))
    }

    /// An IPv6 address without brackets. An IPv4-mapped address
    /// (`::ffff:192.0.2.1`) is the IPv4 host it maps: the dial reaches the
    /// same peer, and client addresses are folded the same way
    /// (`to_canonical`), so it must not be a second mirror, cache tree and
    /// allow-list identity.
    fn ipv6(text: &str) -> Result<Self, HostError> {
        match text.parse::<Ipv6Addr>() {
            Ok(addr) => Ok(match addr.to_ipv4_mapped() {
                Some(v4) => Self(DomainNameInner::Ipv4(v4.to_string().into(), v4)),
                None => Self(DomainNameInner::Ipv6(addr.to_string().into(), addr)),
            }),
            Err(_err @ std::net::AddrParseError { .. }) => {
                // `%` never occurs in an address, so an address before it is
                // a zone (`fe80::1%eth0`, percent-encoded `fe80::1%25eth0`).
                if text
                    .split_once('%')
                    .is_some_and(|(addr, _zone)| addr.parse::<Ipv6Addr>().is_ok())
                {
                    Err(HostError::ZoneId)
                } else {
                    Err(HostError::Invalid)
                }
            }
        }
    }

    /// Return `true` if this domain name is a DNS name, not an address.
    #[must_use]
    #[inline]
    pub(crate) const fn is_dns(&self) -> bool {
        match self {
            Self(DomainNameInner::Dns(_)) => true,
            Self(DomainNameInner::Ipv4(..) | DomainNameInner::Ipv6(..)) => false,
        }
    }

    /// Return `true` if this is a link-local IPv6 address (`fe80::/10`),
    /// which is only reachable through a zone identifier naming the
    /// interface, and the parser refuses zones.
    #[must_use]
    pub(crate) const fn is_ipv6_link_local(&self) -> bool {
        match self {
            Self(DomainNameInner::Ipv6(_, addr)) => addr.is_unicast_link_local(),
            Self(DomainNameInner::Dns(_) | DomainNameInner::Ipv4(..)) => false,
        }
    }

    /// Return `true` if this domain name is an IPv6 address.
    #[must_use]
    #[inline]
    pub(crate) const fn is_ipv6(&self) -> bool {
        match self {
            Self(DomainNameInner::Dns(_) | DomainNameInner::Ipv4(..)) => false,
            Self(DomainNameInner::Ipv6(..)) => true,
        }
    }

    #[must_use]
    #[inline]
    pub(crate) fn as_str(&self) -> &str {
        match self {
            Self(
                DomainNameInner::Dns(s) | DomainNameInner::Ipv4(s, _) | DomainNameInner::Ipv6(s, _),
            ) => s,
        }
    }

    /// Format as a URI authority component (RFC 3986 §3.2).
    ///
    /// IPv6 addresses are bracketed per §3.2.2.
    /// A port is appended with `:` when present.
    ///
    /// This is also the per-host cache directory name
    /// (`cache_paths::CachePaths::host_dir`): only the bracketed form keeps
    /// an IPv6 host with a port (`[2001:db8::1]:8080`) apart from the
    /// portless address that ends in the same digits (`[2001:db8::1:8080]`).
    #[must_use]
    pub(crate) fn format_authority(&self, port: Option<NonZero<u16>>) -> Cow<'_, str> {
        match (self.is_ipv6(), port) {
            (true, Some(port)) => Cow::Owned(format!("[{}]:{port}", self.as_str())),
            (true, None) => Cow::Owned(format!("[{}]", self.as_str())),
            (false, Some(port)) => Cow::Owned(format!("{}:{port}", self.as_str())),
            (false, None) => Cow::Borrowed(self.as_str()),
        }
    }
}

impl std::ops::Deref for DomainName {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.as_str()
    }
}

impl Ord for DomainName {
    fn cmp(&self, other: &Self) -> Ordering {
        self.as_str().cmp(other.as_str())
    }
}

impl PartialOrd for DomainName {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// The URI host form, `format_authority(None)`: an IPv6 address bracketed,
/// so a log line or page appending `:port` or `/path` stays unambiguous.
/// Keys, database rows and list matching use the bare [`DomainName::as_str`].
impl std::fmt::Display for DomainName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.is_ipv6() {
            f.write_str("[")?;
            f.write_str(self.as_str())?;
            f.write_str("]")
        } else {
            self.as_str().fmt(f)
        }
    }
}

/// [`DomainName`]'s `Display` for a host held only as its bare canonical
/// text (`DomainName::as_str`, e.g. a checksum-registry scope): an IPv6
/// address bracketed, so a log line naming it stays unambiguous.
pub(crate) struct HostText<'a>(pub(crate) &'a str);

impl std::fmt::Display for HostText<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self(host) = self;
        // Only an IPv6 address has a colon in its canonical text.
        if host.contains(':') {
            write!(f, "[{host}]")
        } else {
            f.write_str(host)
        }
    }
}

impl PartialEq<str> for DomainName {
    fn eq(&self, other: &str) -> bool {
        self.as_str() == other
    }
}

impl PartialEq<DomainName> for str {
    fn eq(&self, other: &DomainName) -> bool {
        self == other.as_str()
    }
}

impl<'de> Deserialize<'de> for DomainName {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::Error as _;
        let s: String = Deserialize::deserialize(deserializer)?;

        Self::new(&s).map_err(|err| {
            D::Error::custom(format!("Invalid domain `{}`: {err}", s.escape_debug()))
        })
    }
}

impl From<DomainName> for String {
    fn from(val: DomainName) -> Self {
        match val {
            DomainName(
                DomainNameInner::Dns(s) | DomainNameInner::Ipv4(s, _) | DomainNameInner::Ipv6(s, _),
            ) => Self::from(&*s),
        }
    }
}

impl sqlx::Type<sqlx::Sqlite> for DomainName {
    fn type_info() -> <sqlx::Sqlite as sqlx::Database>::TypeInfo {
        <String as sqlx::Type<sqlx::Sqlite>>::type_info()
    }

    fn compatible(ty: &<sqlx::Sqlite as sqlx::Database>::TypeInfo) -> bool {
        <String as sqlx::Type<sqlx::Sqlite>>::compatible(ty)
    }
}

impl<'q> sqlx::Encode<'q, sqlx::Sqlite> for DomainName {
    fn encode_by_ref(
        &self,
        buf: &mut <sqlx::Sqlite as sqlx::Database>::ArgumentBuffer,
    ) -> Result<sqlx::encode::IsNull, sqlx::error::BoxDynError> {
        // The owned copy is unavoidable: SQLite's argument buffer requires
        // 'q-lived text and `self` only lives for this call. Encodes happen
        // on the batched DB task, not per request.
        <String as sqlx::Encode<'q, sqlx::Sqlite>>::encode(self.as_str().to_owned(), buf)
    }
}

impl<'r> sqlx::Decode<'r, sqlx::Sqlite> for DomainName {
    fn decode(
        value: <sqlx::Sqlite as sqlx::Database>::ValueRef<'r>,
    ) -> Result<Self, sqlx::error::BoxDynError> {
        let s = <String as sqlx::Decode<'r, sqlx::Sqlite>>::decode(value)?;
        Self::new(&s).map_err(|err| {
            format!("Invalid domain in database `{}`: {err}", s.escape_debug()).into()
        })
    }
}

// ---------------------------------------------------------------------------
// Host-kind newtypes
// ---------------------------------------------------------------------------
//
// Two semantically distinct flavours of host string exist in this codebase:
//
// * [`ClientHost`] — a validated wire-side host name: what the client put
//   on the wire (`ConnectionDetails::upstream_host`, used for the upstream
//   TCP/TLS connect and the outgoing `Host:` header), and the host of a
//   canonical `Mirror` (the alias' main host, or the client host when no
//   alias matched) that keys the active-downloads registry, the
//   `mirrors_v2` rows and the origins.
// * [`CacheHost`]  — the alias-resolved on-disk identity.  Used for the
//   per-host cache directory, the flat-collision blocklist, and the
//   cleanup/scan filesystem traversal.
//
// Alias resolution happens exactly once, in `request_dispatch::decide_request`;
// every consumer downstream sees the canonical `Mirror`.  Both wrap a
// validated [`DomainName`] and carry the same byte content when no alias
// maps the client name.  Keeping them as distinct types prevents callers
// from accidentally handing a resolved name to a function that expects a
// raw one (and vice versa) — the invariant used to rest on careful variable
// naming alone.
//
// `#[repr(transparent)]` on both wrappers guarantees they share the
// layout of the inner [`DomainName`].  [`ClientHost::as_cache_host`]
// relies on this to return a zero-alloc `&CacheHost` borrow via a
// reference cast (the only `unsafe` block introduced by these
// newtypes).

/// Host name as supplied by the client on the wire (post-validation).
///
/// Stored in [`crate::deb_mirror::Mirror::host`] and in the
/// `mirrors_v2.host` column; threaded into the upstream-connection path
/// (TCP connect, TLS SNI, outgoing `Host:` header).
#[derive(Clone, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
#[repr(transparent)]
pub(crate) struct ClientHost(DomainName);

/// Alias-resolved on-disk identity.
///
/// Equal to [`Alias::main`] when an alias mapping fires for the
/// originating client host, otherwise equal (in byte content) to that
/// client host.  Used by [`crate::cache_layout::ConnectionDetails`] for
/// path construction and by [`crate::flat_blocklist`] as the collision
/// key.
#[derive(Clone, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
#[repr(transparent)]
pub(crate) struct CacheHost(DomainName);

impl ClientHost {
    /// Parse a [`ClientHost`] from a string.
    ///
    /// Returns why if the string is no valid host ([`DomainName::new`]).
    pub(crate) fn new(host: impl AsRef<str>) -> Result<Self, HostError> {
        DomainName::new(host).map(Self)
    }

    /// The host name as a string slice: what `Display` renders, without the
    /// allocation.
    #[must_use]
    #[inline]
    pub(crate) fn as_str(&self) -> &str {
        self.0.as_str()
    }

    /// Convert this client host to a [`CacheHost`] identity, without
    /// allocating.
    #[must_use]
    pub(crate) fn into_cache_host(self) -> CacheHost {
        CacheHost(self.0)
    }

    /// Borrow this client host as its on-disk cache identity, without
    /// allocating.  Encodes the `resolve_alias` fall-back rule (no
    /// alias matched → cache identity equals client host).  Only call
    /// this where the no-alias branch has been observed; otherwise
    /// the borrow would mislabel a non-canonical name as canonical.
    #[must_use]
    pub(crate) fn as_cache_host(&self) -> &CacheHost {
        // Tripwire for a future edit that adds a second field to either
        // wrapper or swaps the inner type for one with different
        // align/size.  The soundness of the cast below rests on
        // `#[repr(transparent)]` being present on both wrappers; that
        // attribute is not directly checkable in `const`, but layout
        // equivalence implies these two equalities.
        const _: () = assert!(
            size_of::<ClientHost>() == size_of::<CacheHost>()
                && align_of::<ClientHost>() == align_of::<CacheHost>(),
            "ClientHost and CacheHost must share layout - one of them lost its #[repr(transparent)] or gained a second field",
        );
        // The assert above only relates the two wrappers to each other:
        // if both grew the same extra field they would still match.
        // `transmute` type-checks only between equal-sized types, so
        // anchoring each wrapper to `DomainName` catches that.
        const _: fn() = || {
            let _ = std::mem::transmute::<ClientHost, DomainName>;
            let _ = std::mem::transmute::<CacheHost, DomainName>;
        };
        // SAFETY: both wrappers are `#[repr(transparent)]` over
        // `DomainName`, so `&ClientHost` and `&CacheHost` share an
        // identical in-memory layout.
        unsafe { &*std::ptr::from_ref(self).cast::<CacheHost>() }
    }
}

impl CacheHost {
    /// The same name as a wire-side [`ClientHost`]: the identity a
    /// canonical `Mirror` carries after alias resolution.
    #[must_use]
    pub(crate) fn to_client_host(&self) -> ClientHost {
        ClientHost(self.0.clone())
    }
}

impl std::ops::Deref for ClientHost {
    type Target = DomainName;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::ops::Deref for CacheHost {
    type Target = DomainName;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::fmt::Display for ClientHost {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl std::fmt::Display for CacheHost {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

// Symmetric `PartialEq<str>` / `PartialEq<ClientHost> for str` mirror
// the impls on `DomainName` so call sites comparing a raw `&str` (e.g.
// `Uri::host()`) against a `ClientHost` need not reach for `.as_str()`.
impl PartialEq<str> for ClientHost {
    fn eq(&self, other: &str) -> bool {
        self.0 == *other
    }
}

impl PartialEq<ClientHost> for str {
    fn eq(&self, other: &ClientHost) -> bool {
        *self == other.0
    }
}

impl From<DomainName> for ClientHost {
    fn from(value: DomainName) -> Self {
        Self(value)
    }
}

impl<'de> Deserialize<'de> for ClientHost {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        DomainName::deserialize(deserializer).map(Self)
    }
}

impl<'de> Deserialize<'de> for CacheHost {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        DomainName::deserialize(deserializer).map(Self)
    }
}

// sqlx delegations: the inner `DomainName` already validates on decode
// and encodes via its `into` to `&String`; both wrappers forward without
// reimplementing the column/type plumbing.
impl sqlx::Type<sqlx::Sqlite> for ClientHost {
    fn type_info() -> <sqlx::Sqlite as sqlx::Database>::TypeInfo {
        <DomainName as sqlx::Type<sqlx::Sqlite>>::type_info()
    }

    fn compatible(ty: &<sqlx::Sqlite as sqlx::Database>::TypeInfo) -> bool {
        <DomainName as sqlx::Type<sqlx::Sqlite>>::compatible(ty)
    }
}

impl<'q> sqlx::Encode<'q, sqlx::Sqlite> for ClientHost {
    fn encode_by_ref(
        &self,
        buf: &mut <sqlx::Sqlite as sqlx::Database>::ArgumentBuffer,
    ) -> Result<sqlx::encode::IsNull, sqlx::error::BoxDynError> {
        <DomainName as sqlx::Encode<'q, sqlx::Sqlite>>::encode_by_ref(&self.0, buf)
    }
}

impl<'r> sqlx::Decode<'r, sqlx::Sqlite> for ClientHost {
    fn decode(
        value: <sqlx::Sqlite as sqlx::Database>::ValueRef<'r>,
    ) -> Result<Self, sqlx::error::BoxDynError> {
        <DomainName as sqlx::Decode<'r, sqlx::Sqlite>>::decode(value).map(Self)
    }
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Alias {
    pub(crate) main: CacheHost,
    pub(crate) aliases: Vec<ClientHost>,
}

/// Resolve a client-supplied host through `aliases` to the on-disk
/// cache identity used by
/// [`crate::cache_layout::ConnectionDetails::cache_dir_path`].
///
/// Returns `Some(&main)` when `host` is listed as an alias of some
/// configured group, otherwise `None` — callers that want the
/// resolved-or-echo shape do `.unwrap_or(...)` themselves.  State
/// keyed on the cache-dir identity (e.g. the flat-collision
/// blocklist) must resolve through this so multiple aliases pointing
/// at the same `main` share keys.
///
/// `aliases[].aliases` is sorted at config load (see `Config::load`),
/// so the inner lookup is a binary search.
#[must_use]
pub(crate) fn resolve_alias<'a>(aliases: &'a [Alias], host: &ClientHost) -> Option<&'a CacheHost> {
    aliases
        .iter()
        .find(|alias| alias.aliases.binary_search(host).is_ok())
        .map(|alias| &alias.main)
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum IpNetOrAddr {
    Net(IpNet),
    Addr(IpAddr),
}

impl IpNetOrAddr {
    /// Whether every address the entry covers is a loopback address.
    #[must_use]
    fn is_loopback(&self) -> bool {
        match self {
            Self::Addr(ip) => ip.is_loopback(),
            Self::Net(net) => net.network().is_loopback() && net.broadcast().is_loopback(),
        }
    }

    #[must_use]
    pub(crate) fn contains(&self, ip: &IpAddr) -> bool {
        match self {
            Self::Addr(ipaddr) => ipaddr == ip,
            Self::Net(ipnet) => ipnet.contains(ip),
        }
    }
}

impl<'de> Deserialize<'de> for IpNetOrAddr {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::Error as _;
        let s: String = Deserialize::deserialize(deserializer)?;

        if let Ok(ip) = s.parse::<IpAddr>() {
            // ClientInfo::ip() folds mapped peers to IPv4, so their ACL
            // entries must use that same identity.
            return Ok(Self::Addr(ip.to_canonical()));
        }

        let net = s.parse::<IpNet>().map_err(D::Error::custom)?.trunc();
        // Only a subnet wholly inside ::ffff:0:0/96 is an IPv4 subnet.
        // Broader IPv6 networks retain their address-family semantics;
        // folding those would unexpectedly admit additional IPv4 clients.
        let net = if let IpNet::V6(v6) = net
            && v6.prefix_len() >= 96
            && let Some(v4) = v6.addr().to_ipv4_mapped()
        {
            IpNet::new(IpAddr::V4(v4), v6.prefix_len() - 96)
                .expect("mapped IPv6 prefix translates to an IPv4 prefix in 0..=32")
        } else {
            net
        };
        Ok(Self::Net(net))
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(from = "String")]
pub(crate) enum LogDestination {
    Console,
    File(PathBuf),
}

impl From<String> for LogDestination {
    fn from(s: String) -> Self {
        if s.eq_ignore_ascii_case("console") {
            Self::Console
        } else {
            Self::File(PathBuf::from(s))
        }
    }
}

/// A `--bind` command line override of [`Config::bind_addr`] and/or
/// [`Config::bind_port`].
///
/// Accepted forms: `ADDR` (`1.2.3.4`, `::1`, `[::1]`), `ADDR:PORT`
/// (`1.2.3.4:3143`, `[::1]:3143`) and `:PORT` (`:3143`).  A bare number is
/// rejected: without a leading colon the value must start with an address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct BindOverride {
    addr: Option<IpAddr>,
    port: Option<NonZero<u16>>,
}

/// Parses a bracketed IPv6 address, e.g. `[::1]`.  Brackets enclose an IPv6
/// address only (RFC 3986 §3.2.2), so `[1.2.3.4]` stays rejected.
fn parse_bracketed_addr(s: &str) -> Option<IpAddr> {
    s.strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .and_then(|inner| inner.parse::<Ipv6Addr>().ok())
        .map(IpAddr::V6)
}

/// Parses the port of a `--bind` value; `input` is the whole value, quoted in
/// the error so the diagnostic names what the user typed.
fn parse_bind_port(port: &str, input: &str) -> Result<NonZero<u16>, String> {
    let value = port
        .parse::<u16>()
        .map_err(|err| format!("invalid port `{port}` in `{input}`: {err}"))?;

    NonZero::new(value)
        .ok_or_else(|| format!("invalid port `{port}` in `{input}`: must not be zero"))
}

impl FromStr for BindOverride {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        const EXPECTED: &str = "expected `ADDR`, `ADDR:PORT` or `:PORT`";

        // An unbracketed IPv6 address is full of colons, so try the whole
        // value as a bare address before the `:PORT` and `ADDR:PORT` forms.
        // `::3143` is a valid IPv6 address and lands here; `:3143` is not
        // (RFC 4291 elision needs `::`) and falls through to the port form.
        if let Ok(addr) = s.parse::<IpAddr>() {
            return Ok(Self {
                addr: Some(addr),
                port: None,
            });
        }

        if let Some(addr) = parse_bracketed_addr(s) {
            return Ok(Self {
                addr: Some(addr),
                port: None,
            });
        }

        // Whatever is left must carry a port.  Split at the last colon rather
        // than parsing a `SocketAddr`, so an out-of-range or zero port is
        // reported as such instead of the whole value being rejected as
        // malformed.  The address half stays empty for the `:PORT` form.
        let Some((addr, port)) = s.rsplit_once(':') else {
            return Err(format!("invalid bind value `{s}`: {EXPECTED}"));
        };

        let addr = if addr.is_empty() {
            None
        } else if let Ok(addr) = addr.parse::<IpAddr>() {
            Some(addr)
        } else if let Some(addr) = parse_bracketed_addr(addr) {
            Some(addr)
        } else {
            return Err(format!("invalid bind value `{s}`: {EXPECTED}"));
        };

        Ok(Self {
            addr,
            port: Some(parse_bind_port(port, s)?),
        })
    }
}

#[expect(clippy::struct_excessive_bools, reason = "configuration")]
#[derive(Debug, Deserialize)]
#[cfg_attr(test, derive(PartialEq))]
#[serde(default, deny_unknown_fields)]
pub(crate) struct Config {
    /// Minimum log level severity to output.
    /// Can be overridden via program options.
    #[serde(deserialize_with = "from_level_name")]
    pub(crate) log_level: LevelFilter,

    /// Path to log file.
    /// The special value `console` will output to the console.
    /// Can be overridden via program options.
    pub(crate) log_file: LogDestination,

    /// Address to listen on; an IPv6 address may be bracketed (`[::1]`), as
    /// `--bind` accepts it.
    #[serde(deserialize_with = "from_bind_addr")]
    pub(crate) bind_addr: IpAddr,

    /// Port to listen on.
    pub(crate) bind_port: NonZero<u16>,

    /// Path to database.
    pub(crate) database_path: PathBuf,

    /// Path to cache directory.
    pub(crate) cache_directory: PathBuf,

    /// Timeout (in seconds) of database operations after which a warning is generated.
    #[serde(deserialize_with = "from_secs_f64")]
    pub(crate) database_slow_timeout: Duration,

    /// Timeout (in seconds) for http operations.
    #[serde(deserialize_with = "from_secs_f64")]
    pub(crate) http_timeout: Duration,

    /// Timeout (in seconds) after which an inbound client connection is closed
    /// while waiting for a complete HTTP request -- covers idle keep-alive
    /// connections and slowloris-style partial header sends.
    ///
    /// Also bounds an established https tunnel (`CONNECT`): a tunnel that
    /// relays no byte in either direction for this long is torn down, so a
    /// parked tunnel cannot pin two file descriptors and an upstream
    /// connection indefinitely (see `connect_tunnel`).
    #[serde(deserialize_with = "from_secs_f64")]
    pub(crate) client_idle_timeout: Duration,

    /// Wall-clock budget (in seconds) for the whole upstream connect-retry
    /// envelope. Retries use a Fibonacci backoff capped at ten retries; a retry
    /// whose delay would finish past this budget is not started and the request
    /// fails terminally instead, so a dead mirror cannot pin an active-download
    /// slot for the full schedule.
    #[serde(deserialize_with = "from_secs_f64")]
    pub(crate) upstream_retry_budget: Duration,

    /// HTTPS upgrade mode.
    pub(crate) https_upgrade_mode: HttpsUpgradeMode,

    /// Size (in bytes) of buffer used for internal data transfer.
    #[serde(deserialize_with = "from_usize_with_magnitude")]
    pub(crate) buffer_size: usize,

    /// Number of stored error and warning log messages.
    pub(crate) logstore_capacity: NonZero<usize>,

    /// Disk quota (in bytes) for cache: the cached files plus the partial
    /// downloads kept for a later resume, each counted rounded up to whole
    /// 4 KiB blocks (`cache_quota::QUOTA_BLOCK_SIZE`) the way it occupies the
    /// disk.
    #[serde(deserialize_with = "from_nonzero_u64_with_magnitude")]
    pub(crate) disk_quota: Option<NonZero<u64>>,

    /// Minimum free disk space (in bytes) to keep on the cache filesystem:
    /// a download that would leave less, counting what the downloads in
    /// flight may still write, is refused with 503 "Disk quota reached"
    /// (like one over `disk_quota`, which it applies without), and
    /// the `/healthcheck` endpoint reports unhealthy below it. `None`
    /// (config value `0`) disables both checks.
    #[serde(deserialize_with = "from_nonzero_u64_with_magnitude")]
    pub(crate) min_disk_free: Option<NonZero<u64>>,

    /// Maximum size (in bytes) of a single upstream object that will be
    /// downloaded and cached. An upstream response declaring a larger
    /// Content-Length is rejected with 502 Bad Gateway before any bytes are
    /// stored. Set to `0` to disable the cap.
    #[serde(deserialize_with = "from_nonzero_u64_with_magnitude")]
    pub(crate) max_object_size: Option<NonZero<u64>>,

    /// Backstop retention time (in days) for files acquired "by-hash".
    ///
    /// By-hash cleanup is primarily *reference-based*: a by-hash file is
    /// reclaimed once its digest is absent from the mirror's current
    /// `Release`/`InRelease` set (after a short grace). This age cap only
    /// applies as a fallback - when no current Release can be read for a
    /// by-hash directory, or for an on-disk digest type the Release does not
    /// list - so it rarely governs disk usage on a healthy mirror.
    pub(crate) byhash_retention_days: NonZero<u64>,

    /// Retention time (in days) for usage logs.
    #[serde(deserialize_with = "from_nonzero_u64")]
    pub(crate) usage_retention_days: Option<NonZero<u64>>,

    /// Mirror aliases.
    pub(crate) aliases: Vec<Alias>,

    /// List of allowed mirrors.
    pub(crate) allowed_mirrors: Vec<ConfigDomainName>,

    /// Ports a proxied request or a followed redirect may name on an
    /// allowed mirror; an absent port is its scheme's default. Like
    /// [`Self::https_tunnel_allowed_ports`] and for the same reason this
    /// list is **fail-open** (empty permits every port), which `validate`
    /// warns about. Without it, listing a host would expose every HTTP
    /// service on it (`http://localhost:9200/`) to the proxy's clients.
    pub(crate) allowed_mirror_ports: Vec<NonZero<u16>>,

    /// List of mirrors supporting only http.
    pub(crate) http_only_mirrors: Vec<ConfigDomainName>,

    /// List of clients permitted to use the proxy.
    /// Empty means all clients are allowed.
    pub(crate) allowed_proxy_clients: Vec<IpNetOrAddr>,

    /// List of clients permitted to use the web-interface.
    /// Empty means all clients are allowed.
    /// None means setting is inherited from `allowed_proxy_clients`.
    pub(crate) allowed_webif_clients: Option<Vec<IpNetOrAddr>>,

    /// Additional DNS names the web interface answers to.  Besides these it
    /// only accepts a `Host` naming an IP literal, `localhost` or the system
    /// hostname; any other name is refused with 421 Misdirected Request so a
    /// DNS-rebinding page cannot read the web interface through a browser
    /// (see `web::host_gate`).
    pub(crate) webif_hostnames: Vec<DomainName>,

    /// Whether https tunneling (`CONNECT`) is enabled.  Off by default: a
    /// tunnel is an open TCP relay to every host in
    /// [`Self::https_tunnel_allowed_mirrors`], so it is enabled together
    /// with that list.
    pub(crate) https_tunnel_enabled: bool,

    /// Allowed ports for https tunneling.  Unlike
    /// [`Self::https_tunnel_allowed_mirrors`] this list is **fail-open**: an
    /// empty list permits every port on an already-permitted host.  The
    /// asymmetry is deliberate (a port list is a narrowing of the host list,
    /// not a second gate), but it is surprising enough that `validate` warns
    /// about it.
    pub(crate) https_tunnel_allowed_ports: Vec<NonZero<u16>>,

    /// Allowed mirrors for https tunneling.  Fail-closed like
    /// [`Self::allowed_mirrors`]: an empty list permits no CONNECT target.
    pub(crate) https_tunnel_allowed_mirrors: Vec<DomainName>,

    /// Maximum number of concurrent HTTPS tunnel connections per client IP.
    /// `None` means unlimited.
    #[serde(deserialize_with = "from_nonzero_usize")]
    pub(crate) https_tunnel_max_connections_per_client: Option<NonZero<usize>>,

    /// Maximum number of concurrent plain-HTTP connections accepted per source
    /// IP address. `None` (configured as 0) means unlimited. Defaults to 128,
    /// which bounds what one source can hold against an idle- or half-open
    /// connection flood while leaving room for many pipelining APT clients
    /// behind one address. Note: clients behind a NAT share a single IP for
    /// this cap.
    #[serde(deserialize_with = "from_nonzero_usize")]
    pub(crate) max_connections_per_client_ip: Option<NonZero<usize>>,

    /// How many leading bits of a client's IPv6 address the per-IP caps
    /// (`max_connections_per_client_ip`,
    /// `https_tunnel_max_connections_per_client`) count it by, 1..=128.
    /// Defaults to 128, every address on its own, like an IPv4 client. A host
    /// picks its addresses from its /64 at will (temporary addresses, or on
    /// purpose), multiplying its cap; 64 closes that, at the price of one
    /// cap for every host of the network -- a LAN's IPv6 clients usually
    /// share one /64 -- which is why it is opt-in.
    pub(crate) client_ipv6_prefix_len: u8,

    /// Maximum number of concurrent accepted connections across all clients
    /// (plain HTTP and CONNECT tunnels alike); excess connections are closed
    /// at accept time.  `None` means unlimited.  Defaults to three quarters
    /// of the soft `RLIMIT_NOFILE` so an idle-connection flood cannot drive
    /// `accept(2)` into `EMFILE` and starve cache files and upstream sockets.
    #[serde(deserialize_with = "from_nonzero_usize")]
    pub(crate) max_connections: Option<NonZero<usize>>,

    /// Minimum transfer rate (in bytes per second) for downloads and uploads.
    /// Connections that fail to fulfill this limit are cancelled.
    #[serde(deserialize_with = "from_nonzero_usize_with_magnitude")]
    pub(crate) min_download_rate: Option<NonZero<usize>>,

    /// Sliding window (in seconds) over which the minimum transfer rate is measured.
    pub(crate) rate_check_timeframe: NonZero<usize>,

    /// Maximum number of concurrent upstream downloads.
    /// `None` means unlimited.
    #[serde(deserialize_with = "from_nonzero_usize")]
    pub(crate) max_upstream_downloads: Option<NonZero<usize>>,

    /// Maximum number of concurrent uncached passthrough relays (requests
    /// the cache declines and forwards as-is), across all clients; further
    /// ones are answered 503. Passthroughs do not count against
    /// `max_upstream_downloads`, except that a cache fetch whose upstream
    /// error answer is relayed holds an upstream-download slot until the
    /// answer arrives and a relay slot while it is relayed.
    /// `None` (configured as 0) means unlimited.
    #[serde(deserialize_with = "from_nonzero_usize")]
    pub(crate) max_passthrough_relays: Option<NonZero<usize>>,

    /// Capacity of the internal database command channel.
    pub(crate) db_channel_capacity: NonZero<usize>,

    /// Maximum number of pending database events buffered before a batch flush.
    pub(crate) db_batch_flush_max_count: NonZero<usize>,

    /// Interval (in seconds) between database batch flushes and mirror
    /// `last_seen` syncs.
    pub(crate) db_batch_flush_interval_secs: NonZero<u64>,

    /// Whether to set `TCP_NODELAY` on upstream sockets (hyper, splice, and
    /// CONNECT tunnels).  Mirror requests are typically a small header
    /// followed by a long body read; disabling Nagle's algorithm avoids the
    /// 40 ms ACK delay the kernel can otherwise add to every request.
    pub(crate) upstream_tcp_nodelay: bool,

    /// Whether to reject differential (pdiff) resource requests with 410 Gone.
    /// When disabled, diff requests are proxied to the upstream mirror but not cached
    /// (while full resources are always cached).
    pub(crate) reject_pdiff_requests: bool,

    /// Whether to verify the integrity of cached content against the
    /// repository's own metadata (by-hash digests, `Packages` checksums,
    /// `Release` checksums) before committing a download to the cache.
    /// Defence in depth: APT's client-side GPG check remains the root of
    /// trust. Verification reads each verifiable file back once before
    /// `rename`; the cost is one extra (page-cache-hot) full read.
    pub(crate) verify_checksums: bool,

    /// Upper bound on the in-memory checksum registry (entries). The registry
    /// maps `(host, mirror_path, resource key)` to an expected digest, populated
    /// by parsing index files as they flow through. At the cap, the oldest
    /// entries are evicted in bulk. One full Debian `main`/amd64 `Packages` is
    /// ~64k entries.
    pub(crate) verify_checksums_max_entries: NonZero<usize>,

    /// Backoff window (in seconds) applied to a resource after its download
    /// failed checksum verification: subsequent requests for it are rejected
    /// with 503 without contacting upstream. The window doubles per
    /// consecutive failure up to `verify_checksums_throttle_cap`; a
    /// successfully verified download clears it. 0 disables the throttle.
    /// Only effective when `verify_checksums` is enabled.
    #[serde(deserialize_with = "from_secs_f64")]
    pub(crate) verify_checksums_throttle_base: Duration,

    /// Upper bound (in seconds) on the exponential verification-failure
    /// backoff window.
    #[serde(deserialize_with = "from_secs_f64")]
    pub(crate) verify_checksums_throttle_cap: Duration,

    /// Whether to answer a cache miss for a large permanent file with a
    /// short error response while the download keeps running, so apt moves
    /// on and late-joins it on its retry.  Undocumented in the shipped
    /// configuration file on purpose; see `parallel_hack` for the
    /// mechanism.  Every option below is inert while this is false.
    pub(crate) experimental_parallel_hack_enabled: bool,

    /// Above this many upstream downloads in flight proxy-wide, no client
    /// is nudged any more.  `None` means no ceiling.
    #[serde(deserialize_with = "from_nonzero_usize")]
    pub(crate) experimental_parallel_hack_maxparallel: Option<NonZero<usize>>,

    /// Status of the nudge response; must be a 4xx or 5xx.
    #[serde(deserialize_with = "statuscode_from_u16")]
    pub(crate) experimental_parallel_hack_statuscode: StatusCode,

    /// `Retry-After` (in seconds) of the nudge response, 1 to 300.
    pub(crate) experimental_parallel_hack_retryafter: u16,

    /// Per-in-flight-download decay of the nudge probability, in `(0, 1]`:
    /// the first download is nudged for certain, each further one less
    /// likely.
    pub(crate) experimental_parallel_hack_factor: f64,

    /// Responses at or below this size are served normally rather than
    /// nudged.  `None` (config value `0`) nudges any size.
    #[serde(deserialize_with = "from_nonzero_u64_with_magnitude")]
    pub(crate) experimental_parallel_hack_minsize: Option<NonZero<u64>>,

    /// Top-level keys the TOML document spelled out, recorded by
    /// [`Self::from_toml`] before deserialization. This is what
    /// [`Self::is_set`] answers from; a value equal to its default is
    /// indistinguishable from an absent key once deserialized.
    #[serde(skip)]
    present: HashSet<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            log_level: LevelFilter::INFO,
            log_file: LogDestination::Console,
            bind_addr: IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            bind_port: nonzero!(3142),
            database_path: PathBuf::from("/var/lib/apt-cacher-rs/apt-cacher-rs.db"),
            cache_directory: PathBuf::from("/var/cache/apt-cacher-rs"),
            database_slow_timeout: Duration::from_secs(2),
            http_timeout: Duration::from_secs(10),
            client_idle_timeout: Duration::from_mins(2),
            upstream_retry_budget: Duration::from_secs(30),
            https_upgrade_mode: HttpsUpgradeMode::Auto,
            buffer_size: 32 * 1024, // 32 KiB
            logstore_capacity: nonzero!(100),
            disk_quota: None,
            min_disk_free: Some(nonzero!(512 * 1024 * 1024)), // 512 MiB
            max_object_size: Some(nonzero!(2 * 1024 * 1024 * 1024)), // 2 GiB
            byhash_retention_days: nonzero!(90),
            usage_retention_days: Some(nonzero!(30)),
            aliases: Vec::new(),
            allowed_mirrors: Vec::new(),
            allowed_mirror_ports: vec![nonzero!(80), nonzero!(443)],
            http_only_mirrors: Vec::new(),
            allowed_proxy_clients: Vec::new(),
            allowed_webif_clients: None,
            webif_hostnames: Vec::new(),
            https_tunnel_enabled: false,
            https_tunnel_allowed_ports: vec![nonzero!(443)],
            https_tunnel_allowed_mirrors: Vec::new(),
            https_tunnel_max_connections_per_client: Some(nonzero!(10)),
            max_connections_per_client_ip: Some(nonzero!(128)),
            client_ipv6_prefix_len: 128,
            max_connections: Some(client_counter::default_max_connections()),
            min_download_rate: Some(nonzero!(10000)), // 10 kB/s
            rate_check_timeframe: DEFAULT_RATE_CHECK_TIMEFRAME,
            max_upstream_downloads: Some(nonzero!(20)),
            max_passthrough_relays: Some(nonzero!(100)),
            db_channel_capacity: nonzero!(128),
            db_batch_flush_max_count: nonzero!(256),
            db_batch_flush_interval_secs: nonzero!(15),
            upstream_tcp_nodelay: true,
            reject_pdiff_requests: true,
            verify_checksums: true,
            verify_checksums_max_entries: nonzero!(500_000),
            verify_checksums_throttle_base: Duration::from_secs(30),
            verify_checksums_throttle_cap: Duration::from_hours(1),
            experimental_parallel_hack_enabled: false,
            experimental_parallel_hack_maxparallel: Some(nonzero!(3)),
            experimental_parallel_hack_statuscode: StatusCode::TOO_MANY_REQUESTS,
            experimental_parallel_hack_retryafter: 5,
            experimental_parallel_hack_factor: 0.2,
            experimental_parallel_hack_minsize: Some(nonzero!(10 * 1024 * 1024)), // 10 MiB
            present: HashSet::new(),
        }
    }
}

fn from_level_name<'de, D>(deserializer: D) -> Result<LevelFilter, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::Error as _;
    let s: String = Deserialize::deserialize(deserializer)?;

    LevelFilter::from_str(&s).map_err(D::Error::custom)
}

/// `bind_addr`: an address, an IPv6 one optionally bracketed.
fn from_bind_addr<'de, D>(deserializer: D) -> Result<IpAddr, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::Error as _;
    let s: String = Deserialize::deserialize(deserializer)?;

    s.parse::<IpAddr>()
        .ok()
        .or_else(|| parse_bracketed_addr(&s))
        .ok_or_else(|| D::Error::custom(format!("invalid IP address `{s}`")))
}

fn from_secs_f64<'de, D>(deserializer: D) -> Result<Duration, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::Error as _;
    let s: f64 = Deserialize::deserialize(deserializer)?;

    Duration::try_from_secs_f64(s).map_err(D::Error::custom)
}

fn from_usize_with_magnitude<'de, D>(deserializer: D) -> Result<usize, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::Error as _;
    let s: String = Deserialize::deserialize(deserializer)?;

    parse_usize_with_magnitude(&s).map_err(D::Error::custom)
}

/// Failure while parsing a magnitude-suffixed size (`42 Gi`).
///
/// Reaches the user through `serde::de::Error::custom`, which only needs
/// `Display`.
#[derive(Debug, thiserror::Error)]
enum MagnitudeError {
    #[error("Invalid number:  {0}")]
    Number(#[from] std::num::ParseIntError),
    #[error("Multiplication overflow")]
    Overflow,
    #[error("Invalid magnitude `{0}`, expected `k`, `Ki`, `M`, `Mi`, `G` or `Gi`")]
    InvalidMagnitude(Box<str>),
}

macro_rules! impl_parse_with_magnitude {
    ($name:ident, $T:ty) => {
        fn $name(s: &str) -> Result<$T, MagnitudeError> {
            let s = s.trim();

            let bare_err = match s.parse::<$T>() {
                Ok(val) => return Ok(val),
                Err(err) => err,
            };

            // Nothing to split on: the value is empty or overflows the
            // target type, so report why the plain number failed rather
            // than blaming a magnitude suffix that was never written.
            let Some(x) = s.find(|c| !char::is_ascii_digit(&c)) else {
                return Err(MagnitudeError::Number(bare_err));
            };

            let (val, mag) = s.split_at(x);

            let val = val.parse::<$T>()?;
            let mag = mag.trim();

            let factor: $T = match mag {
                "k" => 1000,
                "Ki" => 1024,
                "M" => 1000 * 1000,
                "Mi" => 1024 * 1024,
                "G" => 1000 * 1000 * 1000,
                "Gi" => 1024 * 1024 * 1024,
                _ => return Err(MagnitudeError::InvalidMagnitude(mag.into())),
            };

            val.checked_mul(factor).ok_or(MagnitudeError::Overflow)
        }
    };
}

impl_parse_with_magnitude!(parse_usize_with_magnitude, usize);
impl_parse_with_magnitude!(parse_u64_with_magnitude, u64);

fn from_nonzero_usize_with_magnitude<'de, D>(
    deserializer: D,
) -> Result<Option<NonZero<usize>>, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::Error as _;
    let s: String = Deserialize::deserialize(deserializer)?;

    parse_usize_with_magnitude(&s)
        .map(NonZero::new)
        .map_err(D::Error::custom)
}

fn from_nonzero_u64_with_magnitude<'de, D>(
    deserializer: D,
) -> Result<Option<NonZero<u64>>, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::Error as _;
    let s: String = Deserialize::deserialize(deserializer)?;

    parse_u64_with_magnitude(&s)
        .map(NonZero::new)
        .map_err(D::Error::custom)
}

fn statuscode_from_u16<'de, D>(deserializer: D) -> Result<StatusCode, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::Error as _;
    let v: u16 = Deserialize::deserialize(deserializer)?;

    StatusCode::from_u16(v).map_err(D::Error::custom)
}

fn from_nonzero_usize<'de, D>(deserializer: D) -> Result<Option<NonZero<usize>>, D::Error>
where
    D: Deserializer<'de>,
{
    let u: usize = Deserialize::deserialize(deserializer)?;

    Ok(NonZero::new(u))
}

fn from_nonzero_u64<'de, D>(deserializer: D) -> Result<Option<NonZero<u64>>, D::Error>
where
    D: Deserializer<'de>,
{
    let u: u64 = Deserialize::deserialize(deserializer)?;

    Ok(NonZero::new(u))
}

#[must_use]
fn intersect<T: Ord>(a: &[T], b: &[T]) -> bool {
    debug_assert!(
        a.is_sorted(),
        "a must be sorted for the intersection operation"
    );
    debug_assert!(
        b.is_sorted(),
        "b must be sorted for the intersection operation"
    );

    let mut iter_a = a.iter();
    let mut iter_b = b.iter();

    let Some(mut elem_a) = iter_a.next() else {
        return false;
    };
    let Some(mut elem_b) = iter_b.next() else {
        return false;
    };

    loop {
        match elem_a.cmp(elem_b) {
            Ordering::Equal => return true,
            Ordering::Greater => {
                elem_b = match iter_b.next() {
                    Some(n) => n,
                    None => return false,
                }
            }
            Ordering::Less => {
                elem_a = match iter_a.next() {
                    Some(n) => n,
                    None => return false,
                }
            }
        }
    }
}

/// DNS-only label-string validator: caller has already excluded any
/// IPv6/colon form.  All input bytes are required to be ASCII alphanumeric
/// or hyphen; labels must be 1-63 bytes and must not start or end with `-`.
#[must_use]
fn is_valid_dns_label_string(domain: &str) -> bool {
    /* No unicode characters allowed for now */

    let bytes = domain.as_bytes();
    let len = bytes.len();
    if len == 0 || len > 253 {
        return false;
    }

    for part in bytes.split(|&b| b == b'.') {
        let plen = part.len();
        if plen == 0 || plen > 63 {
            return false;
        }
        // RFC 1035: a label must not start or end with a hyphen.  Hoisted
        // out of the inner loop so the per-byte branch is just the
        // alphanumeric-or-hyphen check.
        if part[0] == b'-' || part[plen - 1] == b'-' {
            return false;
        }
        for &b in part {
            if b != b'-' && !b.is_ascii_alphanumeric() {
                return false;
            }
        }
    }

    true
}

/// Validator for a `*.` wildcard allow-list entry (the whole entry, `*`
/// included); every other entry is a host [`DomainName::new`] parses.
///
/// A wildcard must cover at least two further labels — `*.org` would hand
/// a whole TLD to the proxy — and must not look like a partial IPv4
/// address (`*.1.1`), which no `Ipv4Addr`-normalised lookup could ever
/// match.  Everything past the wildcard is the plain DNS label rule, so it
/// is checked by [`is_valid_dns_label_string`].
#[must_use]
fn is_valid_wildcard(domain: &str) -> bool {
    /* No unicode characters allowed for now */

    let Some(suffix) = domain.strip_prefix("*.") else {
        return false;
    };

    suffix.contains('.') && is_valid_dns_label_string(suffix) && !ends_in_a_number(suffix)
}

/// Whether a DNS label string's last label is numeric: all decimal digits,
/// or `0x`/`0X` and hex digits (the WHATWG URL "ends in a number" rule).
/// No top-level domain is numeric (RFC 3696 §2), and `inet_aton`-style
/// resolvers read such a name as an IPv4 address in another notation
/// (`2130706433`, `0x7f.1`, `127.1`, `01.2.3.4`): a second spelling of an
/// address host, with its own cache tree and allow-list identity.
#[must_use]
fn ends_in_a_number(domain: &str) -> bool {
    let last = domain.rsplit('.').next().unwrap_or(domain);
    if !last.is_empty() && last.bytes().all(|b| b.is_ascii_digit()) {
        return true;
    }
    last.strip_prefix("0x")
        .or_else(|| last.strip_prefix("0X"))
        .is_some_and(|hex| hex.bytes().all(|b| b.is_ascii_hexdigit()))
}

/// A URI port: ASCII digits, at least one.
#[must_use]
fn is_port(text: &str) -> bool {
    !text.is_empty() && text.bytes().all(|b| b.is_ascii_digit())
}

/// Warn about a path option that is not absolute.  Such a path still
/// resolves, but against the daemon's working directory (`/` under
/// systemd) rather than where the operator was looking.
fn warn_if_relative(warnings: &mut Vec<String>, key: &str, path: &Path) {
    if !path.is_absolute() {
        warnings.push(format!(
            "{key} `{}` is not an absolute path; it resolves against the daemon working directory (`/` under systemd) - use an absolute path",
            path.display()
        ));
    }
}

/// Outcome of [`Config::load`]: the loaded configuration plus what the
/// caller has to report about how it came about.
#[derive(Debug)]
pub(crate) struct LoadedConfig {
    pub(crate) config: Config,
    /// The default configuration file was absent and the built-in defaults
    /// were used instead.  Never set for an explicitly named file, whose
    /// absence is an error.
    pub(crate) defaults_used: bool,
    /// Non-fatal findings of [`Config::validate`], one log line each.
    pub(crate) warnings: Vec<String>,
}

impl Config {
    /// Load the configuration from the given file.
    ///
    /// When supplied, `cache_directory` overrides [`Self::cache_directory`],
    /// `database_path` overrides [`Self::database_path`] and `bind` overrides
    /// [`Self::bind_addr`] and/or [`Self::bind_port`], applied on top of the
    /// values from the configuration file (or the built-in defaults when no
    /// file is loaded). A non-default `file` that does not exist is always an
    /// error, even when the overrides are supplied.
    pub(crate) fn load(
        file: &Path,
        cache_directory: Option<PathBuf>,
        database_path: Option<PathBuf>,
        bind: Option<BindOverride>,
    ) -> Result<LoadedConfig, ConfigError> {
        let (mut config, defaults_used) = match std::fs::read_to_string(file) {
            Ok(content) => (
                Self::from_toml(&content).map_err(ConfigError::Parse)?,
                false,
            ),
            Err(err)
                if err.kind() == std::io::ErrorKind::NotFound
                    && file == Path::new(DEFAULT_CONFIGURATION_PATH) =>
            {
                (Self::default(), true)
            }
            Err(err) => {
                return Err(ConfigError::Read {
                    path: file.to_path_buf(),
                    source: err,
                });
            }
        };

        if let Some(path) = cache_directory {
            config.cache_directory = path;
        }
        if let Some(path) = database_path {
            config.database_path = path;
        }
        if let Some(bind) = bind {
            config.apply_bind(bind);
        }

        let warnings = config.validate()?;

        Ok(LoadedConfig {
            config,
            defaults_used,
            warnings,
        })
    }

    /// Parse a TOML document, recording which top-level keys it spells out
    /// (see [`Self::is_set`]) before deserializing it without the
    /// [`REMOVED_OPTIONS`].
    ///
    /// Parses to a spanned table first so unknown-key and type errors keep
    /// their line/column information.
    fn from_toml(content: &str) -> Result<Self, toml::de::Error> {
        let mut table = toml::de::DeTable::parse(content)?;
        let present = table
            .get_ref()
            .keys()
            .map(|key| key.get_ref().to_string())
            .collect();
        for key in REMOVED_OPTIONS {
            table.get_mut().remove(*key);
        }
        let mut config = Self::deserialize(toml::de::Deserializer::from(table))?;
        config.present = present;
        Ok(config)
    }

    /// Whether the configuration file spelled out `key` as a top-level entry,
    /// regardless of the value it assigned. `false` for built-in defaults and
    /// CLI overrides.
    fn is_set(&self, key: &str) -> bool {
        self.present.contains(key)
    }

    fn apply_bind(&mut self, bind: BindOverride) {
        let BindOverride { addr, port } = bind;

        if let Some(addr) = addr {
            self.bind_addr = addr;
        }
        if let Some(port) = port {
            self.bind_port = port;
        }
    }

    fn validate(&mut self) -> Result<Vec<String>, ConfigError> {
        let mut warnings: Vec<String> = Vec::new();
        // TODO: check bind_addr.is_documentation() once stable: https://github.com/rust-lang/rust/issues/27709
        if let IpAddr::V6(addr) = self.bind_addr
            && addr.is_unicast_link_local()
        {
            invalid!(
                "Invalid bind_addr `{addr}`: a link-local IPv6 address is bound only together with a zone identifier, which is not supported; listen on `::` or on a global or unique-local address"
            );
        }

        if let LogDestination::File(ref path) = self.log_file {
            if path.as_os_str().is_empty() {
                invalid!("Invalid log_file value: must not be empty");
            }

            warn_if_relative(&mut warnings, "log_file", path);
        }

        // Every timeout shares the same floor and only differs in its
        // ceiling, so they are one table: another timeout is a row here,
        // not a fifth copy of the comparison and the message.
        {
            const MIN_TIMEOUT: Duration = Duration::from_secs(1);

            for (key, value, max) in [
                (
                    "database_slow_timeout",
                    self.database_slow_timeout,
                    Duration::from_mins(1),
                ),
                ("http_timeout", self.http_timeout, Duration::from_mins(6)),
                (
                    "client_idle_timeout",
                    self.client_idle_timeout,
                    Duration::from_hours(1),
                ),
                (
                    "upstream_retry_budget",
                    self.upstream_retry_budget,
                    Duration::from_mins(10),
                ),
            ] {
                if value < MIN_TIMEOUT || value > max {
                    invalid!(
                        "Invalid {key} value of {}s: must be between {}s and {}s",
                        value.as_secs_f32(),
                        MIN_TIMEOUT.as_secs_f32(),
                        max.as_secs_f32()
                    );
                }
            }
        }

        if self.client_idle_timeout < self.http_timeout {
            warnings.push(format!(
                "client_idle_timeout ({}s) is smaller than http_timeout ({}s); slow clients may be disconnected during request-header read while comparable upstream operations are still allowed to complete",
                self.client_idle_timeout.as_secs_f32(),
                self.http_timeout.as_secs_f32()
            ));
        }

        if self.database_slow_timeout > self.http_timeout {
            warnings.push(format!(
                "database_slow_timeout ({}s) is greater than http_timeout ({}s); HTTP requests will time out before slow-database warnings fire",
                self.database_slow_timeout.as_secs_f32(),
                self.http_timeout.as_secs_f32()
            ));
        }

        if self.upstream_retry_budget < self.http_timeout {
            warnings.push(format!(
                "upstream_retry_budget ({}s) is smaller than http_timeout ({}s); a single slow upstream connect can consume the whole envelope, leaving no room to retry",
                self.upstream_retry_budget.as_secs_f32(),
                self.http_timeout.as_secs_f32()
            ));
        }

        if !(1..=128).contains(&self.client_ipv6_prefix_len) {
            invalid!(
                "Invalid client_ipv6_prefix_len value of {}: must be between 1 and 128",
                self.client_ipv6_prefix_len
            );
        }

        if self.buffer_size < 1024 || self.buffer_size > 1024 * 1024 * 1024 {
            invalid!(
                "Invalid buffer_size value of {}: must be between 1KiB and 1GiB",
                self.buffer_size
            );
        }

        if self.buffer_size > 16 * 1024 * 1024 {
            warnings.push(format!(
                "buffer_size of {} is very large; consider a smaller value to avoid excessive memory usage",
                self.buffer_size
            ));
        }

        if let Some(quota) = self.disk_quota
            && quota < nonzero!(200 * 1024 * 1024)
        {
            warnings.push(format!(
                "disk_quota of {} is very small; consider a larger value to avoid requests being rejected",
                HumanFmt::Size(quota.get())
            ));
        }

        if let Some(max_object_size) = self.max_object_size {
            if max_object_size < VOLATILE_UNKNOWN_CONTENT_LENGTH_UPPER {
                invalid!(
                    "Invalid max_object_size value of {max_object_size}: must be at least the volatile unknown content length upper bound of {VOLATILE_UNKNOWN_CONTENT_LENGTH_UPPER}"
                )
            }

            if max_object_size < nonzero!(100 * 1024 * 1024) {
                warnings.push(format!(
                    "max_object_size of {} is very small; consider a larger value to avoid requests being rejected",
                    HumanFmt::Size(max_object_size.get())
                ));
            }
            if let Some(quota) = self.disk_quota
                && max_object_size > quota
            {
                warnings.push(format!(
                    "max_object_size of {} exceeds disk_quota ({}); the smaller bound (disk_quota) wins",
                    max_object_size.get(),
                    quota.get()
                ));
            }
        }

        if self
            .byhash_retention_days
            .checked_mul(nonzero!(24 * 60 * 60))
            .is_none()
        {
            invalid!(
                "Invalid byhash_retention_days value of {}: Overflow",
                self.byhash_retention_days
            );
        }

        if self.byhash_retention_days > nonzero!(365) {
            warnings.push(format!(
                "byhash_retention_days of {} is very large; consider a smaller value to avoid excessive disk usage",
                self.byhash_retention_days.get()
            ));
        }

        if let Some(days) = self.usage_retention_days
            && days.checked_mul(nonzero!(24 * 60 * 60)).is_none()
        {
            invalid!(
                "Invalid usage_retention_days value of {}: Overflow",
                days.get()
            );
        }

        if self.db_channel_capacity > nonzero!(4096) {
            invalid!(
                "Invalid db_channel_capacity value of {}: must be between 1 and 4096",
                self.db_channel_capacity
            );
        }

        if self.db_batch_flush_max_count > nonzero!(4096) {
            invalid!(
                "Invalid db_batch_flush_max_count value of {}: must be between 1 and 4096",
                self.db_batch_flush_max_count
            );
        }

        if self.db_batch_flush_interval_secs > nonzero!(300) {
            invalid!(
                "Invalid db_batch_flush_interval_secs value of {}: must be between 1 and 300",
                self.db_batch_flush_interval_secs
            );
        }

        // Alias validation
        {
            for alias in &mut self.aliases {
                alias.aliases.sort_unstable();
            }

            for (pos, alias) in self.aliases.iter().enumerate() {
                let remaining_aliases = &self.aliases.as_slice()[pos + 1..];

                if let Some(falias) = remaining_aliases.iter().find(|ialias| {
                    ialias.main == alias.main
                        || ialias
                            .aliases
                            .binary_search_by_key(&alias.main.as_str(), |a| a.as_str())
                            .is_ok()
                        || alias
                            .aliases
                            .binary_search_by_key(&ialias.main.as_str(), |a| a.as_str())
                            .is_ok()
                        || intersect(&ialias.aliases, &alias.aliases)
                }) {
                    invalid!("Alias {} conflicts with alias {}", alias.main, falias.main);
                }
            }
        }

        self.allowed_mirror_ports.sort_unstable();
        self.https_tunnel_allowed_ports.sort_unstable();
        self.https_tunnel_allowed_mirrors.sort_unstable();

        if !self.allowed_mirrors.is_empty() {
            for mirror in &self.http_only_mirrors {
                let Some(mirror) = mirror.host() else {
                    continue;
                };

                if !self.allowed_mirrors.iter().any(|a| a.permits(mirror)) {
                    warnings.push(format!(
                        "http_only_mirrors entry `{mirror}` is not permitted by allowed_mirrors"
                    ));
                }
            }
        }

        if !self.allowed_mirrors.is_empty() {
            for alias in &self.aliases {
                if !self.allowed_mirrors.iter().any(|a| a.permits(&alias.main)) {
                    warnings.push(format!(
                        "alias target `{}` is not permitted by allowed_mirrors",
                        alias.main
                    ));
                }
            }
        }

        // A link-local address is only reachable through a zone identifier,
        // which the host parser refuses (a zone names an interface of this
        // machine, not a mirror). The entry parses, so say why every dial
        // of it will fail.
        let link_local = [
            (
                "allowed_mirrors",
                self.allowed_mirrors
                    .iter()
                    .filter_map(ConfigDomainName::host)
                    .collect::<Vec<_>>(),
            ),
            (
                "http_only_mirrors",
                self.http_only_mirrors
                    .iter()
                    .filter_map(ConfigDomainName::host)
                    .collect(),
            ),
            (
                "aliases",
                self.aliases
                    .iter()
                    .flat_map(|alias| {
                        std::iter::once::<&DomainName>(&alias.main)
                            .chain(alias.aliases.iter().map(|a| &**a))
                    })
                    .collect(),
            ),
            (
                "https_tunnel_allowed_mirrors",
                self.https_tunnel_allowed_mirrors.iter().collect(),
            ),
        ];
        for (key, hosts) in link_local {
            for host in hosts.into_iter().filter(|h| h.is_ipv6_link_local()) {
                warnings.push(format!(
                    "{key} entry `{host}` is a link-local IPv6 address, reachable only through a zone identifier, which is not supported; every connection to it fails (list a global or unique-local address of the mirror)"
                ));
            }
        }

        if !self.https_tunnel_enabled {
            for key in [
                "https_tunnel_allowed_ports",
                "https_tunnel_allowed_mirrors",
                "https_tunnel_max_connections_per_client",
            ] {
                if self.is_set(key) {
                    warnings.push(format!(
                        "{key} is set but has no effect while https_tunnel_enabled is false"
                    ));
                }
            }
        }

        if self.allowed_mirror_ports.is_empty() {
            warnings.push(
                "allowed_mirror_ports is empty, which permits requests to every port on an allowed mirror (unlike allowed_mirrors, where empty permits nothing); list the ports to restrict them"
                    .to_string(),
            );
        } else if self
            .allowed_mirror_ports
            .binary_search(&nonzero!(443))
            .is_err()
        {
            // An https upgrade of a mirror named without a port dials 443.
            match self.https_upgrade_mode {
                HttpsUpgradeMode::Always => invalid!(
                    "Invalid allowed_mirror_ports: https_upgrade_mode is Always, which fetches a mirror named without a port over https on port 443, but 443 is not listed"
                ),
                HttpsUpgradeMode::Auto => warnings.push(
                    "allowed_mirror_ports does not list 443, so mirrors named without a port are fetched over plain http although https_upgrade_mode is Auto; list 443 or set https_upgrade_mode to Never"
                        .to_string(),
                ),
                HttpsUpgradeMode::Never => {}
            }
        }

        // Both client lists fail open when empty. The proxy one is empty as
        // shipped, so an operator who only fills in `allowed_mirrors` serves
        // every host that can reach the listener. Until `allowed_mirrors` is
        // filled in the proxy serves nothing and `main` warns about that
        // instead, so neither warning below fires for the shipped defaults.
        let configured = !self.allowed_mirrors.is_empty();
        if configured && self.allowed_proxy_clients.is_empty() {
            warnings.push(
                "allowed_proxy_clients is empty, so every host that can reach the listener may use the proxy; list the client networks it should serve"
                    .to_string(),
            );
        }

        // The web interface shows the logs, every client's address and
        // traffic, and the mirror URLs (a private repository's token
        // included); inheriting the proxy list hands that to every client.
        if configured
            && self.allowed_webif_clients.is_none()
            && (self.allowed_proxy_clients.is_empty()
                || !self
                    .allowed_proxy_clients
                    .iter()
                    .all(IpNetOrAddr::is_loopback))
        {
            warnings.push(
                "allowed_webif_clients is unset, so the web interface admits every proxy client, and shows each of them the logs, the other clients' addresses and traffic, and the mirror URLs; set allowed_webif_clients to the administrators' addresses (e.g. ['127.0.0.1', '::1'])"
                    .to_string(),
            );
        }

        // Tunneling is off by default, so reaching here means the operator
        // enabled it without listing a single permitted target.
        if self.https_tunnel_enabled && self.https_tunnel_allowed_mirrors.is_empty() {
            warnings.push(
                "https_tunnel_enabled is true but https_tunnel_allowed_mirrors is empty; every CONNECT request will be refused (list the tunnel targets, or disable https_tunnel_enabled)"
                    .to_string(),
            );
        }

        if self.https_upgrade_mode == HttpsUpgradeMode::Never && !self.https_tunnel_enabled {
            warnings.push(
                "https_upgrade_mode is Never and https_tunnel_enabled is false; clients have no encrypted path to mirrors"
                    .to_string(),
            );
        }

        // The sibling mirror list is fail-closed, so an operator who clears
        // this one is likely expecting "no ports" rather than "every port".
        if self.https_tunnel_enabled && self.https_tunnel_allowed_ports.is_empty() {
            warnings.push(
                "https_tunnel_allowed_ports is empty, which permits CONNECT to every port on a permitted mirror (unlike https_tunnel_allowed_mirrors, where empty permits nothing); list the ports to restrict them"
                    .to_string(),
            );
        }

        if self.https_tunnel_enabled {
            const TYPICAL_TLS_PORTS: &[u16] = &[443, 8443];

            let unusual = self
                .https_tunnel_allowed_ports
                .iter()
                .filter(|p| !TYPICAL_TLS_PORTS.contains(&p.get()))
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ");
            if !unusual.is_empty() {
                warnings.push(format!(
                    "https_tunnel_allowed_ports contains non-TLS-typical port(s): {unusual}"
                ));
            }
        }

        // Deliberately a value comparison, not `is_set`: this is a hard
        // error, and spelling out the default (`rate_check_timeframe = 30`)
        // next to a disabled `min_download_rate` must keep starting the daemon.
        if self.min_download_rate.is_none()
            && self.rate_check_timeframe != DEFAULT_RATE_CHECK_TIMEFRAME
        {
            invalid!(
                "rate_check_timeframe is set to {}s but min_download_rate is disabled",
                self.rate_check_timeframe
            );
        }

        if self.is_set("client_ipv6_prefix_len")
            && self.max_connections_per_client_ip.is_none()
            && (!self.https_tunnel_enabled
                || self.https_tunnel_max_connections_per_client.is_none())
        {
            warnings.push(
                "client_ipv6_prefix_len is set but has no effect while no per-client cap (max_connections_per_client_ip, https_tunnel_max_connections_per_client) is active"
                    .to_string(),
            );
        }

        if self.rate_check_timeframe > nonzero!(360) {
            invalid!(
                "Invalid rate_check_timeframe value of {}s: must be between 1s and 360s",
                self.rate_check_timeframe
            );
        }

        if self.min_download_rate.is_some() && self.rate_check_timeframe < nonzero!(5) {
            warnings.push(format!(
                "rate_check_timeframe of {}s is very short; consider at least 5s to avoid premature cancellations",
                self.rate_check_timeframe
            ));
        }

        for key in REMOVED_OPTIONS {
            if self.is_set(key) {
                warnings.push(format!(
                    "{key} is no longer supported and is ignored; remove it from the configuration"
                ));
            }
        }

        if !self.experimental_parallel_hack_enabled
            && [
                "experimental_parallel_hack_maxparallel",
                "experimental_parallel_hack_statuscode",
                "experimental_parallel_hack_retryafter",
                "experimental_parallel_hack_factor",
                "experimental_parallel_hack_minsize",
            ]
            .into_iter()
            .any(|key| self.is_set(key))
        {
            warnings.push(
                "experimental_parallel_hack options are set but experimental_parallel_hack_enabled is false".to_string(),
            );
        }

        if !self.experimental_parallel_hack_factor.is_normal()
            || self.experimental_parallel_hack_factor <= 0.0
            || self.experimental_parallel_hack_factor > 1.0
        {
            invalid!(
                "Invalid experimental_parallel_hack_factor of {}: must be between 0 and 1",
                self.experimental_parallel_hack_factor
            );
        }

        if self.experimental_parallel_hack_retryafter < 1
            || self.experimental_parallel_hack_retryafter > 300
        {
            invalid!(
                "Invalid experimental_parallel_hack_retryafter value of {}: must be between 1 and 300",
                self.experimental_parallel_hack_retryafter
            );
        }

        if !self.experimental_parallel_hack_statuscode.is_client_error()
            && !self.experimental_parallel_hack_statuscode.is_server_error()
        {
            invalid!(
                "Invalid experimental_parallel_hack_statuscode of {}: must be a 4xx or 5xx status",
                self.experimental_parallel_hack_statuscode
            );
        }

        if self.experimental_parallel_hack_enabled
            && let Some(minsize) = self.experimental_parallel_hack_minsize
            && let Some(quota) = self.disk_quota
            && minsize > quota
        {
            warnings.push(format!(
                "experimental_parallel_hack_minsize ({minsize}) is greater than disk_quota ({quota}); the hack will never trigger"
            ));
        }

        if self.verify_checksums && self.verify_checksums_max_entries.get() < 10_000 {
            warnings.push(format!(
                "verify_checksums_max_entries ({}) is very low; checksum verification coverage of .deb files will be poor",
                self.verify_checksums_max_entries
            ));
        }

        if self.verify_checksums_throttle_cap < self.verify_checksums_throttle_base {
            warnings.push(format!(
                "verify_checksums_throttle_cap ({}s) is below verify_checksums_throttle_base ({}s); the cap will be raised to the base",
                self.verify_checksums_throttle_cap.as_secs_f64(),
                self.verify_checksums_throttle_base.as_secs_f64()
            ));
        }

        if !self.verify_checksums {
            // An explicit 0 means deliberately disabled -- no warning.
            for (name, value) in [
                (
                    "verify_checksums_throttle_base",
                    self.verify_checksums_throttle_base,
                ),
                (
                    "verify_checksums_throttle_cap",
                    self.verify_checksums_throttle_cap,
                ),
            ] {
                if self.is_set(name) && !value.is_zero() {
                    warnings.push(format!(
                        "{name} ({}s) has no effect while verify_checksums is disabled",
                        value.as_secs_f64()
                    ));
                }
            }
        }

        if self.cache_directory.as_os_str().is_empty() {
            invalid!("Invalid cache_directory value: must not be empty");
        }
        warn_if_relative(&mut warnings, "cache_directory", &self.cache_directory);

        if self.database_path.as_os_str().is_empty() {
            invalid!("Invalid database_path value: must not be empty");
        }
        warn_if_relative(&mut warnings, "database_path", &self.database_path);

        Ok(warnings)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::error::ErrorReport;

    fn client_acls(entry: &str) -> Config {
        Config::from_toml(&format!(
            "allowed_proxy_clients = ['{entry}']\nallowed_webif_clients = ['{entry}']"
        ))
        .expect("valid client ACLs")
    }

    #[test]
    fn mapped_client_acls_match_their_ipv4_address_or_subnet() {
        use crate::{client_info::ClientInfo, request_dispatch::client_permitted};

        for (mapped, plain, inside, outside) in [
            ("::ffff:192.0.2.1", "192.0.2.1", "192.0.2.1", "192.0.2.2"),
            ("::FFFF:c000:201", "192.0.2.1", "192.0.2.1", "192.0.2.2"),
            (
                "::ffff:192.0.2.129/120",
                "192.0.2.0/24",
                "192.0.2.255",
                "192.0.3.1",
            ),
            (
                "::ffff:192.0.2.1/128",
                "192.0.2.1/32",
                "192.0.2.1",
                "192.0.2.2",
            ),
            ("::ffff:0:0/96", "0.0.0.0/0", "203.0.113.1", "::1"),
        ] {
            let config = client_acls(mapped);
            let canonical = client_acls(plain);
            assert_eq!(
                config.allowed_proxy_clients, canonical.allowed_proxy_clients,
                "{mapped}"
            );
            assert_eq!(
                config.allowed_webif_clients, canonical.allowed_webif_clients,
                "{mapped}"
            );
            let v4: Ipv4Addr = inside.parse().expect("IPv4 test client");
            for (ip, permitted) in [
                (IpAddr::V4(v4), true),
                (IpAddr::V6(v4.to_ipv6_mapped()), true),
                (outside.parse().expect("excluded test client"), false),
            ] {
                let client = ClientInfo::new(std::net::SocketAddr::new(ip, 1234));
                for acl in [
                    config.allowed_proxy_clients.as_slice(),
                    config.allowed_webif_clients.as_deref().expect("web ACL"),
                ] {
                    assert_eq!(client_permitted(acl, &client), permitted, "{mapped}, {ip}");
                }
            }
        }
    }

    #[test]
    fn native_and_broad_ipv6_client_acls_keep_their_address_family() {
        for (entry, inside) in [
            ("::192.0.2.1", "::192.0.2.1"),
            ("2001:db8::1234/64", "2001:db8::1"),
            ("::ffff:192.0.2.1/95", "::fffe:192.0.2.1"),
            ("::/0", "::1"),
        ] {
            let config = client_acls(entry);
            let acl = &config.allowed_proxy_clients[0];
            assert!(
                matches!(
                    acl,
                    IpNetOrAddr::Addr(IpAddr::V6(_)) | IpNetOrAddr::Net(IpNet::V6(_))
                ),
                "{entry}"
            );
            assert!(
                acl.contains(&inside.parse().expect("IPv6 client")),
                "{entry}"
            );
            assert!(
                !acl.contains(&IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))),
                "{entry}"
            );
        }
    }

    fn bind(s: &str) -> BindOverride {
        let parsed = s.parse::<BindOverride>();
        assert!(parsed.is_ok(), "`{s}` should parse: {parsed:?}");
        parsed.expect("asserted above")
    }

    #[test]
    fn test_bind_override_address_only() {
        for (input, expected) in [
            ("1.2.3.4", IpAddr::from(Ipv4Addr::new(1, 2, 3, 4))),
            ("0.0.0.0", IpAddr::from(Ipv4Addr::UNSPECIFIED)),
            ("::1", IpAddr::from(Ipv6Addr::LOCALHOST)),
            ("::", IpAddr::from(Ipv6Addr::UNSPECIFIED)),
            ("[::1]", IpAddr::from(Ipv6Addr::LOCALHOST)),
            // A valid IPv6 address, not port 3143 - RFC 4291 elision needs `::`.
            (
                "::3143",
                IpAddr::from(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0x3143)),
            ),
        ] {
            assert_eq!(
                bind(input),
                BindOverride {
                    addr: Some(expected),
                    port: None,
                },
                "input `{input}`"
            );
        }
    }

    #[test]
    fn test_bind_override_address_and_port() {
        assert_eq!(
            bind("1.2.3.4:3143"),
            BindOverride {
                addr: Some(IpAddr::from(Ipv4Addr::new(1, 2, 3, 4))),
                port: Some(nonzero!(3143_u16)),
            }
        );
        assert_eq!(
            bind("[::1]:3143"),
            BindOverride {
                addr: Some(IpAddr::from(Ipv6Addr::LOCALHOST)),
                port: Some(nonzero!(3143_u16)),
            }
        );
    }

    #[test]
    fn test_bind_override_port_only() {
        assert_eq!(
            bind(":3143"),
            BindOverride {
                addr: None,
                port: Some(nonzero!(3143_u16)),
            }
        );
        assert_eq!(
            bind(":1"),
            BindOverride {
                addr: None,
                port: Some(nonzero!(1_u16)),
            }
        );
    }

    #[test]
    fn test_bind_override_rejected() {
        for input in [
            "",                // empty
            "3143",            // bare port needs a leading colon
            ":",               // no port digits
            ":0",              // port zero
            ":65536",          // port out of range
            ":-1",             // negative port
            "0.0.0.0:0",       // port zero
            "1.2.3.4:",        // no port digits
            "1.2.3.4:70000",   // port out of range
            "1.2.3.256",       // not an address
            "localhost",       // no name resolution
            "localhost:3143",  // no name resolution
            "[::1",            // unbalanced bracket
            "::1]",            // unbalanced bracket
            "[1.2.3.4]",       // brackets are IPv6-only
            "1.2.3.4:3143:80", // trailing garbage
        ] {
            assert!(
                input.parse::<BindOverride>().is_err(),
                "`{input}` should be rejected"
            );
        }
    }

    #[test]
    fn test_bind_override_error_messages() {
        for (input, expected) in [
            (":0", "invalid port `0` in `:0`: must not be zero"),
            (
                "0.0.0.0:0",
                "invalid port `0` in `0.0.0.0:0`: must not be zero",
            ),
            (
                ":65536",
                "invalid port `65536` in `:65536`: number too large to fit in target type",
            ),
            (
                "1.2.3.4:70000",
                "invalid port `70000` in `1.2.3.4:70000`: number too large to fit in target type",
            ),
            (
                "localhost:3143",
                "invalid bind value `localhost:3143`: expected `ADDR`, `ADDR:PORT` or `:PORT`",
            ),
            (
                "3143",
                "invalid bind value `3143`: expected `ADDR`, `ADDR:PORT` or `:PORT`",
            ),
        ] {
            assert_eq!(
                input.parse::<BindOverride>().unwrap_err(),
                expected,
                "input `{input}`"
            );
        }
    }

    #[test]
    fn test_bind_override_applied() {
        let base = Config::default;

        let mut config = base();
        config.apply_bind(bind("127.0.0.1"));
        assert_eq!(config.bind_addr, IpAddr::from(Ipv4Addr::LOCALHOST));
        assert_eq!(config.bind_port, nonzero!(3142_u16));

        let mut config = base();
        config.apply_bind(bind(":3143"));
        assert_eq!(config.bind_addr, IpAddr::from(Ipv6Addr::UNSPECIFIED));
        assert_eq!(config.bind_port, nonzero!(3143_u16));

        let mut config = base();
        config.apply_bind(bind("127.0.0.1:3143"));
        assert_eq!(config.bind_addr, IpAddr::from(Ipv4Addr::LOCALHOST));
        assert_eq!(config.bind_port, nonzero!(3143_u16));
    }

    /// The configuration file takes an IPv6 `bind_addr` bare or bracketed,
    /// like `--bind` does, and nothing else.
    #[test]
    fn bind_addr_accepts_a_bracketed_ipv6_address() {
        for (input, expected) in [
            ("::1", IpAddr::from(Ipv6Addr::LOCALHOST)),
            ("[::1]", IpAddr::from(Ipv6Addr::LOCALHOST)),
            ("[::]", IpAddr::from(Ipv6Addr::UNSPECIFIED)),
            ("127.0.0.1", IpAddr::from(Ipv4Addr::LOCALHOST)),
        ] {
            let config = Config::from_toml(&format!("bind_addr = '{input}'\n")).unwrap();
            assert_eq!(config.bind_addr, expected, "input `{input}`");
        }
        for input in ["[127.0.0.1]", "[::1]:3142", "::1%eth0", "localhost", ""] {
            assert!(
                Config::from_toml(&format!("bind_addr = '{input}'\n")).is_err(),
                "input `{input}` parsed"
            );
        }
    }

    /// A link-local `bind_addr` would need a zone identifier to bind, so it
    /// is refused up front, from the file and from `--bind` alike.
    #[test]
    fn a_link_local_bind_addr_is_invalid() {
        let mut config = Config::from_toml("bind_addr = 'fe80::1'\n").expect("config parses");
        let err = config.validate().expect_err("link-local accepted");
        assert!(err.to_string().contains("link-local IPv6 address"), "{err}");

        let mut config = Config::default();
        config.apply_bind(bind("[fe80::1]:3143"));
        assert!(config.validate().is_err());

        let mut config = Config::default();
        config.apply_bind(bind("[fd00::1]:3143"));
        config.validate().expect("a unique-local address is fine");
    }

    #[test]
    fn test_parse_size_with_magnitude() {
        assert_eq!(0, parse_usize_with_magnitude("0").unwrap());

        assert_eq!(1024, parse_usize_with_magnitude("1024").unwrap());

        assert!(parse_usize_with_magnitude("0x1000").is_err());

        assert!(parse_usize_with_magnitude("-9999").is_err());

        assert_eq!(1000, parse_usize_with_magnitude("1k").unwrap());

        assert_eq!(1024, parse_usize_with_magnitude("1Ki").unwrap());

        assert_eq!(42_000_000_000, parse_usize_with_magnitude("42 G").unwrap());

        assert_eq!(45_097_156_608, parse_usize_with_magnitude("42 Gi").unwrap());

        assert!(parse_usize_with_magnitude("1K").is_err());

        assert!(parse_usize_with_magnitude("987ki").is_err());

        assert!(parse_usize_with_magnitude("-9M").is_err());

        assert!(parse_usize_with_magnitude("-7 y").is_err());
    }

    #[test]
    fn test_parse_u64_with_magnitude() {
        assert_eq!(0, parse_u64_with_magnitude("0").unwrap());

        assert_eq!(1024, parse_u64_with_magnitude("1024").unwrap());

        assert_eq!(1000, parse_u64_with_magnitude("1k").unwrap());

        assert_eq!(1024, parse_u64_with_magnitude("1Ki").unwrap());

        assert_eq!(1_000_000, parse_u64_with_magnitude("1M").unwrap());

        assert_eq!(0x0010_0000, parse_u64_with_magnitude("1Mi").unwrap());

        assert_eq!(42_000_000_000, parse_u64_with_magnitude("42 G").unwrap());

        assert_eq!(45_097_156_608, parse_u64_with_magnitude("42 Gi").unwrap());

        assert!(parse_u64_with_magnitude("1K").is_err());

        assert!(parse_u64_with_magnitude("-9M").is_err());
    }

    #[test]
    fn test_magnitude_without_a_suffix_reports_the_number_error() {
        // An empty value and an all-digit value that overflows share the
        // "nothing to split on" branch; the diagnostic must name the
        // number, not a magnitude suffix that was never written.
        for input in ["", "   ", "99999999999999999999999999"] {
            let err = parse_u64_with_magnitude(input).expect_err("must not parse");
            assert!(
                err.to_string().starts_with("Invalid number:"),
                "input `{input}`: {err}"
            );
        }
    }

    #[test]
    fn test_domain_name_new() {
        // Mirrors the accept/reject set that `DomainName::new` enforces,
        // which is the same set `cleanup_invalid_rows` uses to purge bad
        // mirror rows before `flat_blocklist::init` runs.
        fn accepts(s: &str) -> bool {
            DomainName::new(s).is_ok()
        }

        assert!(accepts("debian.org"));
        assert!(accepts("salsa.debian.org"));
        assert!(accepts("metadata.ftp-master.debian.org"));

        // empty
        assert!(!accepts(""));

        // double dots
        assert!(!accepts("debian..org"));

        // short part
        assert!(accepts("debian.f.org"));

        // too long part
        assert!(!accepts(
            "debian.abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789AAA.org"
        ));

        // starting dash
        assert!(!accepts("-debian.org"));

        // ending dash
        assert!(!accepts("debian-.org"));

        // dash in positions 2-5
        assert!(accepts("d-ebian.org"));
        assert!(accepts("de-bian.org"));
        assert!(accepts("deb-ian.org"));
        assert!(accepts("debi-an.org"));

        // invalid char
        assert!(!accepts("deb_ian.org"));

        // special directory entries
        assert!(!accepts("."));
        assert!(!accepts(".."));
        assert!(!accepts("foo/bar"));

        // wild card
        assert!(!accepts("*.debian.org"));
        assert!(!accepts("*e.debian.org"));
        assert!(!accepts("deb.*.debian.org"));
        assert!(!accepts("debian.*"));

        // IPv4 addresses (DomainName routes these through `Ipv4Addr::parse`)
        assert!(accepts("192.168.1.1"));
        assert!(accepts("10.0.0.1"));
        assert!(accepts("127.0.0.1"));
        assert!(accepts("255.255.255.255"));

        // IPv6 addresses
        assert!(accepts("::1"));
        assert!(accepts("2001:db8::1"));
        assert!(accepts("fe80::1"));
        assert!(accepts("::ffff:192.168.1.1"));
        assert!(accepts("2001:0db8:0000:0000:0000:0000:0000:0001"));

        // invalid IPv6
        assert!(!accepts(":::1"));
        assert!(!accepts("2001:db8::xyz"));
        assert!(!accepts("2001:db8::1::2"));
    }

    /// Every spelling of an IPv6 host parses to one value whose text is the
    /// bare RFC 5952 form; that text parses back to the same value.
    #[test]
    fn an_ipv6_host_parses_bare_or_bracketed_to_one_canonical_value() {
        let canonical = dn("2001:db8::1");
        for spelling in [
            "2001:db8::1",
            "[2001:db8::1]",
            "[2001:DB8::1]",
            "2001:0db8:0:0:0:0:0:1",
            "[2001:0db8:0000:0000:0000:0000:0000:0001]",
        ] {
            assert_eq!(
                DomainName::new(spelling),
                Ok(canonical.clone()),
                "{spelling}"
            );
        }
        assert_eq!(canonical.as_str(), "2001:db8::1");
        assert_eq!(canonical.format_authority(None), "[2001:db8::1]");
        assert_eq!(canonical.to_string(), "[2001:db8::1]", "logs bracket it");
        for host in ["2001:db8::1", "deb.debian.org", "192.0.2.1"] {
            assert_eq!(
                HostText(host).to_string(),
                dn(host).to_string(),
                "bare text renders like its host"
            );
        }
        assert_eq!(dn("DEB.debian.org").to_string(), "deb.debian.org");
        assert_eq!(dn("[0:0::1]").as_str(), "::1");

        for host in [
            "deb.debian.org",
            "DEB.debian.ORG",
            "192.0.2.1",
            "::1",
            "[::1]",
        ] {
            let parsed = dn(host);
            assert_eq!(DomainName::new(parsed.as_str()), Ok(parsed), "{host}");
        }
    }

    #[test]
    fn a_host_rejection_names_its_reason() {
        for (input, reason) in [
            ("fe80::1%eth0", HostError::ZoneId),
            ("[fe80::1%eth0]", HostError::ZoneId),
            ("[fe80::1%25eth0]", HostError::ZoneId),
            ("[2001:db8::1]:8080", HostError::Port),
            ("deb.debian.org:80", HostError::Port),
            ("192.0.2.1:80", HostError::Port),
            ("[2001:db8::1", HostError::Invalid),
            ("[2001:db8::1]x", HostError::Invalid),
            ("[2001:db8::1]:", HostError::Invalid),
            ("[deb.debian.org]", HostError::Invalid),
            ("[192.0.2.1]", HostError::Invalid),
            ("[]", HostError::Invalid),
            ("foo%bar", HostError::Invalid),
            ("deb.debian.org:http", HostError::Invalid),
        ] {
            assert_eq!(DomainName::new(input), Err(reason), "{input}");
        }
    }

    /// A name whose last label is numeric is an IPv4 address in another
    /// notation to a resolver, so it is refused with its own reason; a
    /// numeric label elsewhere, or a hex-looking one that is no number, is
    /// an ordinary name.
    #[test]
    fn a_name_ending_in_a_number_is_refused() {
        for numeric in [
            "2130706433",
            "1.2.3",
            "127.1",
            "01.2.3.4",
            "0x7f.0.0.1",
            "deb.0x7F",
            "example.0x",
            "192.168.1.256",
        ] {
            assert_eq!(
                DomainName::new(numeric),
                Err(HostError::NumericName),
                "{numeric}"
            );
            assert!(ConfigDomainName::new(numeric).is_err(), "{numeric}");
        }
        assert!(ConfigDomainName::new("*.example.123").is_err());
        for name in [
            "1.example.org",
            "deb9.debian.org",
            "0xdeb.example",
            "example.0xg",
        ] {
            assert!(DomainName::new(name).is_ok(), "{name}");
        }
    }

    /// The configuration takes the parser's hosts, IPv6 bare or bracketed,
    /// and the error names the reason.
    #[test]
    fn a_config_entry_takes_a_bracketed_ipv6_host() {
        let cfg = Config::from_toml(
            "allowed_mirrors = ['[2001:db8::1]', '2001:db8::2']\n\
             https_tunnel_allowed_mirrors = ['[2001:DB8::3]']\n\
             aliases = [ ['[2001:db8::1]', ['[2001:db8::4]']] ]\n",
        )
        .expect("bracketed IPv6 hosts are valid configuration");
        let allowed: Vec<_> = cfg
            .allowed_mirrors
            .iter()
            .map(ConfigDomainName::host)
            .collect();
        assert_eq!(
            allowed,
            [Some(&dn("2001:db8::1")), Some(&dn("2001:db8::2"))]
        );
        assert_eq!(cfg.https_tunnel_allowed_mirrors, [dn("2001:db8::3")]);
        assert!(
            resolve_alias(&cfg.aliases, &clh("2001:db8::4"))
                .is_some_and(|main| main.as_str() == "2001:db8::1")
        );

        for (entry, reason) in [
            ("[2001:db8::1]:8080", "a host must not carry a port"),
            ("[fe80::1%eth0]", "IPv6 zone identifiers are not supported"),
            ("deb_ian.org", "not a valid DNS name or IP address"),
        ] {
            let err = Config::from_toml(&format!("allowed_mirrors = ['{entry}']\n"))
                .expect_err("invalid entry");
            let rendered = format!("{}", ErrorReport(&err));
            assert!(
                rendered.contains(&format!("Invalid configuration domain `{entry}`: {reason}")),
                "{entry}: {rendered}"
            );
        }
    }

    #[test]
    fn test_accepts_config() {
        fn accepts_config(s: &str) -> bool {
            ConfigDomainName::new(s).is_ok()
        }

        assert!(accepts_config("debian.org"));

        assert!(accepts_config("salsa.debian.org"));

        assert!(accepts_config("metadata.ftp-master.debian.org"));

        // empty
        assert!(!accepts_config(""));

        // double dots
        assert!(!accepts_config("debian..org"));

        // short part
        assert!(accepts_config("debian.f.org"));

        // too long part
        assert!(!accepts_config(
            "debian.abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789AAA.org"
        ));

        // starting dash
        assert!(!accepts_config("-debian.org"));

        // ending dash
        assert!(!accepts_config("debian-.org"));

        // dash in position 2
        assert!(accepts_config("d-ebian.org"));

        // dash in position 3
        assert!(accepts_config("de-bian.org"));

        // dash in position 4
        assert!(accepts_config("deb-ian.org"));

        // dash in position 5
        assert!(accepts_config("debi-an.org"));

        // invalid char
        assert!(!accepts_config("deb_ian.org"));

        // special directory entry
        assert!(!accepts_config("."));
        assert!(!accepts_config(".."));
        assert!(!accepts_config("foo/bar"));

        // wild card
        assert!(accepts_config("*.debian.org"));
        assert!(!accepts_config("*e.debian.org"));
        assert!(!accepts_config("deb.*.debian.org"));
        assert!(!accepts_config("debian.*"));

        // wildcard minimum depth (must have at least 3 parts)
        assert!(!accepts_config("*.org"));
        assert!(!accepts_config("*.com"));
        assert!(accepts_config("*.debian.org"));
        assert!(accepts_config("*.ftp.debian.org"));

        // a wildcard is the whole first label and nothing else
        assert!(!accepts_config("*"));
        assert!(!accepts_config("*."));
        assert!(!accepts_config("**.debian.org"));
        assert!(!accepts_config("*-.debian.org"));
        assert!(!accepts_config("*.debian.org."));

        // IPv4 addresses
        assert!(accepts_config("192.168.1.1"));
        assert!(accepts_config("10.0.0.1"));
        assert!(accepts_config("127.0.0.1"));
        assert!(accepts_config("255.255.255.255"));

        // IPv6 addresses
        assert!(accepts_config("::1"));
        assert!(accepts_config("2001:db8::1"));
        assert!(accepts_config("fe80::1"));
        assert!(accepts_config("::ffff:192.168.1.1"));
        assert!(accepts_config("2001:0db8:0000:0000:0000:0000:0000:0001"));

        // invalid IPv6
        assert!(!accepts_config(":::1"));
        assert!(!accepts_config("2001:db8::xyz"));
        assert!(!accepts_config("2001:db8::1::2"));

        // bracketed IPv6, but no port and no wildcard around an address
        assert!(accepts_config("[2001:db8::1]"));
        assert!(!accepts_config("[2001:db8::1]:8080"));
        assert!(!accepts_config("*.[2001:db8::1]"));

        // Wildcards that look like partial IPv4 addresses
        assert!(!accepts_config("*.1.1"));
        assert!(!accepts_config("*.168.1.1"));
        assert!(!accepts_config("*.0.0.1"));
    }

    // -----------------------------------------------------------------
    // Alias resolution + host-wrapper helpers
    // -----------------------------------------------------------------

    fn dn(s: &str) -> DomainName {
        DomainName::new(s).expect("test input must be a valid domain")
    }

    fn clh(s: &str) -> ClientHost {
        ClientHost::new(s).expect("test input must be a valid domain")
    }

    fn cah(s: &str) -> CacheHost {
        CacheHost(dn(s))
    }

    /// Build an `Alias` group with the alias list pre-sorted, matching
    /// the invariant `Config::validate` enforces at load time.
    fn alias_group(main: &str, aliases: &[&str]) -> Alias {
        let mut aliases: Vec<ClientHost> = aliases.iter().map(|s| clh(s)).collect();
        aliases.sort_unstable();
        Alias {
            main: cah(main),
            aliases,
        }
    }

    #[test]
    fn domain_names_are_case_insensitive() {
        // DNS is case-insensitive; a mixed-case request host must map onto
        // the same cache tree, mirror row and allow-list entry.
        let host = DomainName::new("DEB.Debian.ORG").expect("valid");
        assert_eq!(host.as_str(), "deb.debian.org");
        let exact = ConfigDomainName::new("Deb.debian.org").expect("valid");
        assert!(exact.permits(&host));
        assert_eq!(exact.host(), Some(&host));
        let wildcard = ConfigDomainName::new("*.Debian.ORG").expect("valid");
        assert!(wildcard.permits(&host));
    }

    /// An entry and a host compare as parsed values: every spelling of an
    /// address is the one host, and a wildcard never admits an address.
    #[test]
    fn an_entry_permits_every_spelling_of_its_host() {
        let entry = ConfigDomainName::new("[2001:db8::1]").expect("valid");
        for spelling in ["2001:db8::1", "[2001:DB8::1]", "[2001:db8:0:0::1]"] {
            assert!(entry.permits(&dn(spelling)), "{spelling}");
        }
        assert!(!entry.permits(&dn("2001:db8::2")));

        let wildcard = ConfigDomainName::new("*.example.org").expect("valid");
        assert!(wildcard.permits(&dn("deb.example.org")));
        assert!(!wildcard.permits(&dn("example.org")));
        assert!(!wildcard.permits(&dn("192.0.2.1")));
    }

    #[test]
    fn resolve_alias_empty_slice_returns_none() {
        let aliases: [Alias; 0] = [];
        assert!(resolve_alias(&aliases, &clh("deb.debian.org")).is_none());
    }

    #[test]
    fn resolve_alias_hit_returns_main() {
        let aliases = [alias_group(
            "deb.debian.org",
            &[
                "ftp.de.debian.org",
                "ftp.us.debian.org",
                "ftp.fr.debian.org",
            ],
        )];
        let resolved = resolve_alias(&aliases, &clh("ftp.us.debian.org")).expect("alias matches");
        assert_eq!(resolved.as_str(), "deb.debian.org");
    }

    #[test]
    fn resolve_alias_main_is_not_self_alias() {
        // Mains are not implicitly registered as aliases of themselves;
        // a request *to* the main returns `None` so the cache identity
        // falls back to the client host (which equals the main here).
        let aliases = [alias_group("deb.debian.org", &["ftp.de.debian.org"])];
        assert!(resolve_alias(&aliases, &clh("deb.debian.org")).is_none());
    }

    #[test]
    fn resolve_alias_multi_group_picks_owning_group() {
        let aliases = [
            alias_group("deb.debian.org", &["ftp.de.debian.org"]),
            alias_group("archive.ubuntu.com", &["de.archive.ubuntu.com"]),
        ];
        let resolved =
            resolve_alias(&aliases, &clh("de.archive.ubuntu.com")).expect("alias matches");
        assert_eq!(resolved.as_str(), "archive.ubuntu.com");
    }

    #[test]
    fn resolve_alias_empty_aliases_group_does_not_break_search() {
        // A configured group with no aliases must not be considered a
        // match for any host (and must not corrupt subsequent groups).
        let aliases = [
            alias_group("solo.example.com", &[]),
            alias_group("deb.debian.org", &["ftp.de.debian.org"]),
        ];
        assert!(resolve_alias(&aliases, &clh("solo.example.com")).is_none());
        let hit = resolve_alias(&aliases, &clh("ftp.de.debian.org")).expect("alias matches");
        assert_eq!(hit.as_str(), "deb.debian.org");
    }

    #[test]
    fn resolve_alias_unknown_host_returns_none() {
        let aliases = [alias_group("deb.debian.org", &["ftp.de.debian.org"])];
        assert!(resolve_alias(&aliases, &clh("apt.llvm.org")).is_none());
    }

    #[test]
    fn client_host_into_cache_host_preserves_inner() {
        let client = clh("example.test");
        let cache = client.clone().into_cache_host();
        assert_eq!(cache.as_str(), "example.test");
        assert_eq!(client.as_str(), cache.as_str());
    }

    #[test]
    fn client_host_as_cache_host_zero_alloc_view() {
        // Both wrappers are `#[repr(transparent)]` around `DomainName`,
        // so `as_cache_host` returns a borrow with identical bytes.
        let client = clh("example.test");
        let cache_view = client.as_cache_host();
        assert_eq!(client.as_str(), cache_view.as_str());
        assert_eq!(
            std::ptr::from_ref(client.as_str()).addr(),
            std::ptr::from_ref(cache_view.as_str()).addr(),
        );
    }

    #[test]
    fn client_host_cross_kind_equality() {
        let client = clh("example.test");
        let cache = cah("example.test");
        let other = cah("other.test");
        assert_eq!(*client, *cache);
        assert_eq!(*cache, *client);
        assert_ne!(*client, *other);
        assert_ne!(*other, *client);
    }

    #[test]
    fn host_wrapper_deref_exposes_format_helpers() {
        // `Deref<Target = DomainName>` is the contract every caller
        // relies on for `as_str` / `format_authority`.
        let client = clh("example.test");
        let cache = cah("example.test");
        let port = NonZero::new(8080);
        assert_eq!(client.format_authority(port).as_ref(), "example.test:8080");
        assert_eq!(cache.format_authority(port).as_ref(), "example.test:8080");
    }

    #[test]
    fn verify_checksums_defaults_on() {
        let cfg = Config::from_toml("").expect("empty config parses");
        assert!(cfg.verify_checksums);
        assert_eq!(cfg.verify_checksums_max_entries.get(), 500_000);
    }

    #[test]
    fn verify_checksums_can_be_disabled() {
        let cfg = Config::from_toml("verify_checksums = false").expect("config parses");
        assert!(!cfg.verify_checksums);
    }

    #[test]
    fn verify_throttle_defaults() {
        let cfg = Config::from_toml("").expect("empty config parses");
        assert_eq!(cfg.verify_checksums_throttle_base, Duration::from_secs(30));
        assert_eq!(cfg.verify_checksums_throttle_cap, Duration::from_hours(1));
    }

    #[test]
    fn verify_throttle_overrides_parse() {
        let cfg = Config::from_toml(
            "verify_checksums_throttle_base = 0.5\nverify_checksums_throttle_cap = 60",
        )
        .expect("config parses");
        assert_eq!(
            cfg.verify_checksums_throttle_base,
            Duration::from_millis(500)
        );
        assert_eq!(cfg.verify_checksums_throttle_cap, Duration::from_mins(1));
    }

    #[test]
    fn verify_throttle_cap_below_base_warns() {
        let mut cfg = Config::from_toml(
            "verify_checksums_throttle_base = 60\nverify_checksums_throttle_cap = 30",
        )
        .expect("config parses");
        let warnings = cfg.validate().expect("config validates");
        assert!(
            warnings
                .iter()
                .any(|w| w.contains("the cap will be raised to the base")),
            "expected cap-below-base warning, got: {warnings:?}"
        );
    }

    #[test]
    fn verify_throttle_set_while_verify_off_warns() {
        let mut cfg = Config::from_toml(
            "verify_checksums = false\nverify_checksums_throttle_base = 60\nverify_checksums_throttle_cap = 120",
        )
        .expect("config parses");
        let warnings = cfg.validate().expect("config validates");
        assert_eq!(
            warnings
                .iter()
                .filter(|w| w.contains("has no effect while verify_checksums is disabled"))
                .count(),
            2,
            "expected warnings for both throttle options, got: {warnings:?}"
        );
    }

    #[test]
    fn verify_throttle_explicit_defaults_while_verify_off_warn() {
        // Presence, not value, decides: spelling out the default values is
        // still "set" and still has no effect.
        let mut cfg = Config::from_toml(
            "verify_checksums = false\nverify_checksums_throttle_base = 30\nverify_checksums_throttle_cap = 3600",
        )
        .expect("config parses");
        let warnings = cfg.validate().expect("config validates");
        assert_eq!(
            warnings
                .iter()
                .filter(|w| w.contains("has no effect while verify_checksums is disabled"))
                .count(),
            2,
            "expected warnings for both throttle options, got: {warnings:?}"
        );
    }

    #[test]
    fn verify_throttle_unset_or_zero_while_verify_off_do_not_warn() {
        for toml_input in [
            "verify_checksums = false",
            "verify_checksums = false\nverify_checksums_throttle_base = 0\nverify_checksums_throttle_cap = 0",
        ] {
            let mut cfg = Config::from_toml(toml_input).expect("config parses");
            let warnings = cfg.validate().expect("config validates");
            assert!(
                !warnings
                    .iter()
                    .any(|w| w.contains("has no effect while verify_checksums is disabled")),
                "unexpected warning for `{toml_input}`: {warnings:?}"
            );
        }
    }

    // -----------------------------------------------------------------
    // Defaults and key presence
    // -----------------------------------------------------------------

    fn warnings_for(toml_input: &str) -> Vec<String> {
        let mut cfg = Config::from_toml(toml_input).expect("config parses");
        cfg.validate().expect("config validates")
    }

    /// A link-local address parses (without its zone) but can never be
    /// dialled, so every list naming one warns, once per entry; a global
    /// address does not.
    #[test]
    fn a_link_local_entry_warns_in_every_host_list() {
        let warnings = warnings_for(
            "allowed_mirrors = ['fe80::1', '2001:db8::1', '[fe80::2]']\n\
             http_only_mirrors = ['fe80::1']\n\
             aliases = [ ['fe80::1', ['fe80::3', 'deb.example.org']] ]\n\
             https_tunnel_enabled = true\n\
             https_tunnel_allowed_mirrors = ['fe80::4']\n",
        );
        let link_local: Vec<_> = warnings
            .iter()
            .filter(|w| w.contains("is a link-local IPv6 address"))
            .collect();
        for expected in [
            "allowed_mirrors entry `[fe80::1]`",
            "allowed_mirrors entry `[fe80::2]`",
            "http_only_mirrors entry `[fe80::1]`",
            "aliases entry `[fe80::1]`",
            "aliases entry `[fe80::3]`",
            "https_tunnel_allowed_mirrors entry `[fe80::4]`",
        ] {
            assert!(
                link_local.iter().any(|w| w.starts_with(expected)),
                "{expected}: {link_local:?}"
            );
        }
        assert_eq!(link_local.len(), 6, "{link_local:?}");
    }

    /// An IPv4-mapped IPv6 address is the IPv4 host it maps, as a client
    /// address is: one mirror, one cache tree, one allow-list entry.
    #[test]
    fn an_ipv4_mapped_address_is_its_ipv4_host() {
        let v4 = dn("192.0.2.1");
        for spelling in [
            "::ffff:192.0.2.1",
            "[::ffff:192.0.2.1]",
            "[::FFFF:c000:201]",
        ] {
            assert_eq!(dn(spelling), v4, "{spelling}");
        }
        assert!(!dn("[::ffff:192.0.2.1]").is_ipv6());
        assert!(
            ConfigDomainName::new("192.0.2.1")
                .expect("valid")
                .permits(&dn("[::ffff:192.0.2.1]"))
        );
        // Only the mapped block folds: the deprecated IPv4-compatible form
        // stays an IPv6 address.
        assert!(dn("::192.0.2.1").is_ipv6());
    }

    #[test]
    fn an_open_client_list_warns() {
        let open = |w: &String| w.starts_with("allowed_proxy_clients is empty");
        let webif = |w: &String| w.starts_with("allowed_webif_clients is unset");

        // As shipped: no mirror, so the proxy serves nobody yet and the
        // `allowed_mirrors` warning is the one to act on.
        let warnings = warnings_for("");
        assert!(!warnings.iter().any(open), "{warnings:?}");
        assert!(!warnings.iter().any(webif), "{warnings:?}");

        let warnings = warnings_for("allowed_mirrors = ['deb.debian.org']\n");
        assert!(warnings.iter().any(open), "{warnings:?}");
        assert!(warnings.iter().any(webif), "{warnings:?}");

        let warnings = warnings_for(
            "allowed_mirrors = ['deb.debian.org']\nallowed_proxy_clients = ['192.168.0.0/16', '::1']\n",
        );
        assert!(!warnings.iter().any(open), "{warnings:?}");
        assert!(
            warnings.iter().any(webif),
            "a LAN list is inherited: {warnings:?}"
        );

        for quiet in [
            "allowed_proxy_clients = ['127.0.0.1', '::1', '127.0.0.0/8']\n",
            "allowed_proxy_clients = ['192.168.0.0/16']\nallowed_webif_clients = ['::1']\n",
            "allowed_proxy_clients = ['192.168.0.0/16']\nallowed_webif_clients = []\n",
        ] {
            let warnings = warnings_for(&format!("allowed_mirrors = ['deb.debian.org']\n{quiet}"));
            assert!(!warnings.iter().any(webif), "{quiet}: {warnings:?}");
        }
        let warnings = warnings_for(
            "allowed_mirrors = ['deb.debian.org']\nallowed_proxy_clients = ['127.0.0.0/7']\n",
        );
        assert!(
            warnings.iter().any(webif),
            "a net reaching past loopback: {warnings:?}"
        );
    }

    /// The two tunnel ACLs have opposite empty-list semantics: an empty
    /// mirror list refuses every CONNECT, an empty port list permits every
    /// port. Both cases must be called out, or clearing the port list reads
    /// as "no ports" and silently widens the relay.
    #[test]
    fn both_empty_tunnel_acls_warn() {
        let warnings = warnings_for(
            "https_tunnel_enabled = true\nhttps_tunnel_allowed_ports = []\nhttps_tunnel_allowed_mirrors = []\n",
        );
        assert!(
            warnings
                .iter()
                .any(|w| w.contains("https_tunnel_allowed_ports is empty")),
            "an empty port list is fail-open and must warn: {warnings:?}"
        );
        assert!(
            warnings
                .iter()
                .any(|w| w.contains("https_tunnel_allowed_mirrors is empty")),
            "an empty mirror list is fail-closed and must warn: {warnings:?}"
        );

        let restricted = warnings_for(
            "https_tunnel_enabled = true\nhttps_tunnel_allowed_ports = [443]\nhttps_tunnel_allowed_mirrors = ['deb.debian.org']\nallowed_mirrors = ['deb.debian.org']\n",
        );
        assert!(
            !restricted
                .iter()
                .any(|w| w.contains("https_tunnel_allowed")),
            "a fully specified tunnel config must not warn: {restricted:?}"
        );
    }

    #[test]
    fn client_ipv6_prefix_len_is_bounded_and_warns_without_a_cap() {
        for invalid in ["client_ipv6_prefix_len = 0", "client_ipv6_prefix_len = 129"] {
            let mut cfg = Config::from_toml(invalid).expect("parses");
            assert!(cfg.validate().is_err(), "{invalid}");
        }
        let no_effect =
            |w: &String| w.starts_with("client_ipv6_prefix_len is set but has no effect");
        assert!(
            !warnings_for("client_ipv6_prefix_len = 48")
                .iter()
                .any(no_effect)
        );
        assert!(
            warnings_for("client_ipv6_prefix_len = 48\nmax_connections_per_client_ip = 0")
                .iter()
                .any(no_effect)
        );
    }

    #[test]
    fn allowed_mirror_ports_without_443_conflicts_with_https_upgrade() {
        let mut always =
            Config::from_toml("allowed_mirror_ports = [80]\nhttps_upgrade_mode = 'Always'")
                .expect("parses");
        assert!(always.validate().is_err());
        let no_443 = |w: &String| w.starts_with("allowed_mirror_ports does not list 443");
        assert!(
            warnings_for("allowed_mirror_ports = [80]")
                .iter()
                .any(no_443)
        );
        assert!(
            !warnings_for("allowed_mirror_ports = [80]\nhttps_upgrade_mode = 'Never'")
                .iter()
                .any(no_443)
        );
        assert!(
            !warnings_for("allowed_mirror_ports = [80, 443]")
                .iter()
                .any(no_443)
        );
    }

    #[test]
    fn default_equals_empty_document() {
        // Struct-level `#[serde(default)]` makes the empty document and
        // `Default` the same value; the built-in fallback in `Config::load`
        // relies on that.
        let parsed = Config::from_toml("").expect("empty config parses");
        assert_eq!(parsed, Config::default());
        assert!(parsed.present.is_empty());

        let warnings = Config::default().validate().expect("defaults validate");
        assert!(warnings.is_empty(), "defaults must not warn: {warnings:?}");
    }

    #[test]
    fn passthrough_relay_cap_defaults_to_100_and_zero_disables_it() {
        let default = Config::from_toml("").expect("empty config parses");
        assert_eq!(default.max_passthrough_relays, Some(nonzero!(100)));
        let disabled = Config::from_toml("max_passthrough_relays = 0").expect("0 parses");
        assert_eq!(disabled.max_passthrough_relays, None);
    }

    #[test]
    fn per_client_ip_cap_defaults_to_128_and_zero_disables_it() {
        let default = Config::from_toml("").expect("empty config parses");
        assert_eq!(default.max_connections_per_client_ip, Some(nonzero!(128)));

        let disabled = Config::from_toml("max_connections_per_client_ip = 0").expect("0 parses");
        assert_eq!(disabled.max_connections_per_client_ip, None);

        let custom = Config::from_toml("max_connections_per_client_ip = 16").expect("16 parses");
        assert_eq!(custom.max_connections_per_client_ip, Some(nonzero!(16)));
    }

    #[test]
    fn is_set_records_top_level_keys_regardless_of_value() {
        let cfg = Config::from_toml(
            "bind_port = 3142\nhttps_tunnel_enabled = true\naliases = []\n[[unused_table]]",
        )
        .expect_err("unknown table is rejected");
        assert!(
            cfg.to_string().contains("unused_table"),
            "unknown-key error names the key: {cfg}"
        );

        let cfg = Config::from_toml("bind_port = 3142\nhttps_tunnel_enabled = true\naliases = []")
            .expect("config parses");
        assert!(cfg.is_set("bind_port"));
        assert!(cfg.is_set("https_tunnel_enabled"));
        assert!(cfg.is_set("aliases"));
        assert!(!cfg.is_set("bind_addr"));
        assert!(!cfg.is_set("log_file"));
        assert!(!Config::default().is_set("bind_port"));
    }

    #[test]
    fn https_tunnel_options_explicit_defaults_while_disabled_warn() {
        let warnings = warnings_for(
            "https_tunnel_enabled = false\n\
             https_tunnel_allowed_ports = [443]\n\
             https_tunnel_allowed_mirrors = []\n\
             https_tunnel_max_connections_per_client = 10",
        );
        for key in [
            "https_tunnel_allowed_ports",
            "https_tunnel_allowed_mirrors",
            "https_tunnel_max_connections_per_client",
        ] {
            assert!(
                warnings.iter().any(|w| w
                    == &format!(
                        "{key} is set but has no effect while https_tunnel_enabled is false"
                    )),
                "expected no-effect warning for {key}, got: {warnings:?}"
            );
        }
    }

    #[test]
    fn https_tunnel_options_unset_or_enabled_do_not_warn() {
        for toml_input in [
            "https_tunnel_enabled = false",
            "https_tunnel_enabled = true\nhttps_tunnel_allowed_ports = [443]\nhttps_tunnel_max_connections_per_client = 10",
        ] {
            let warnings = warnings_for(toml_input);
            assert!(
                !warnings
                    .iter()
                    .any(|w| w.contains("has no effect while https_tunnel_enabled is false")),
                "unexpected warning for `{toml_input}`: {warnings:?}"
            );
        }
    }

    #[test]
    fn parallel_hack_options_explicit_defaults_while_disabled_warn() {
        const NEEDLE: &str = "experimental_parallel_hack options are set but experimental_parallel_hack_enabled is false";
        for line in [
            "experimental_parallel_hack_maxparallel = 3",
            "experimental_parallel_hack_statuscode = 429",
            "experimental_parallel_hack_retryafter = 5",
            "experimental_parallel_hack_factor = 0.2",
            "experimental_parallel_hack_minsize = '10Mi'",
        ] {
            let warnings = warnings_for(line);
            assert!(
                warnings.iter().any(|w| w == NEEDLE),
                "expected no-effect warning for `{line}`, got: {warnings:?}"
            );
        }

        for toml_input in [
            "",
            "experimental_parallel_hack_enabled = false",
            "experimental_parallel_hack_enabled = true\nexperimental_parallel_hack_maxparallel = 3",
        ] {
            let warnings = warnings_for(toml_input);
            assert!(
                !warnings.iter().any(|w| w == NEEDLE),
                "unexpected warning for `{toml_input}`: {warnings:?}"
            );
        }
    }

    #[test]
    fn parallel_hack_statuscode_outside_4xx_5xx_is_invalid() {
        for statuscode in [100, 200, 301] {
            let mut cfg = Config::from_toml(&format!(
                "experimental_parallel_hack_statuscode = {statuscode}"
            ))
            .expect("config parses");
            let err = cfg.validate().expect_err(&format!(
                "statuscode {statuscode} is neither 4xx nor 5xx and must be rejected"
            ));
            assert!(
                err.to_string().contains(&format!(
                    "Invalid experimental_parallel_hack_statuscode of {statuscode}"
                )),
                "unexpected error for statuscode {statuscode}: {err}"
            );
        }

        for statuscode in [400, 429, 500, 599] {
            let mut cfg = Config::from_toml(&format!(
                "experimental_parallel_hack_statuscode = {statuscode}"
            ))
            .expect("config parses");
            let result = cfg.validate();
            assert!(
                result.is_ok(),
                "statuscode {statuscode} is a valid 4xx/5xx status: {result:?}"
            );
        }
    }

    /// A removed option still loads, whatever value it carries, so an old
    /// configuration file does not stop the daemon from starting; it only
    /// earns a warning naming the key.
    #[test]
    fn removed_mmap_threshold_is_ignored_with_a_warning() {
        const WARNING: &str = "mmap_threshold is no longer supported and is ignored; remove it from the configuration";
        for value in ["1048576", "0", "'1M'"] {
            let warnings = warnings_for(&format!("mmap_threshold = {value}"));
            assert!(
                warnings.iter().any(|w| w == WARNING),
                "mmap_threshold = {value}: {warnings:?}"
            );
        }
        assert!(
            !warnings_for("")
                .iter()
                .any(|w| w.contains("mmap_threshold")),
            "unset mmap_threshold must not warn"
        );
    }

    // -----------------------------------------------------------------
    // Range and path validation
    // -----------------------------------------------------------------

    fn error_for(toml_input: &str) -> String {
        let mut cfg = Config::from_toml(toml_input).expect("config parses");
        cfg.validate()
            .expect_err("configuration must be rejected")
            .to_string()
    }

    #[test]
    fn timeouts_outside_their_range_are_rejected() {
        for (key, above) in [
            ("database_slow_timeout", "61"),
            ("http_timeout", "361"),
            ("client_idle_timeout", "3601"),
            ("upstream_retry_budget", "601"),
        ] {
            for value in ["0.5", above] {
                let err = error_for(&format!("{key} = {value}"));
                assert!(
                    err.starts_with(&format!("Invalid {key} value of")),
                    "unexpected error for `{key} = {value}`: {err}"
                );
            }
        }

        // Pin the exact wording once; the four checks share one message.
        assert_eq!(
            error_for("http_timeout = 361"),
            "Invalid http_timeout value of 361s: must be between 1s and 360s"
        );
    }

    #[test]
    fn numeric_options_just_past_their_range_are_rejected() {
        // One row per `validate` rule, each one step past its bound; the
        // twin at the bound is in `numeric_options_at_their_bounds_are_accepted`.
        for (input, expected) in [
            (
                "buffer_size = '1023'",
                "Invalid buffer_size value of 1023: must be between 1KiB and 1GiB",
            ),
            (
                "buffer_size = '1073741825'",
                "Invalid buffer_size value of 1073741825: must be between 1KiB and 1GiB",
            ),
            (
                "max_object_size = '1048575'",
                "Invalid max_object_size value of 1048575: must be at least the volatile unknown content length upper bound of 1048576",
            ),
            (
                "byhash_retention_days = 213503982334602",
                "Invalid byhash_retention_days value of 213503982334602: Overflow",
            ),
            (
                "usage_retention_days = 213503982334602",
                "Invalid usage_retention_days value of 213503982334602: Overflow",
            ),
            (
                "db_channel_capacity = 4097",
                "Invalid db_channel_capacity value of 4097: must be between 1 and 4096",
            ),
            (
                "db_batch_flush_max_count = 4097",
                "Invalid db_batch_flush_max_count value of 4097: must be between 1 and 4096",
            ),
            (
                "db_batch_flush_interval_secs = 301",
                "Invalid db_batch_flush_interval_secs value of 301: must be between 1 and 300",
            ),
            (
                "min_download_rate = '0'\nrate_check_timeframe = 31",
                "rate_check_timeframe is set to 31s but min_download_rate is disabled",
            ),
            (
                "min_download_rate = '1000'\nrate_check_timeframe = 361",
                "Invalid rate_check_timeframe value of 361s: must be between 1s and 360s",
            ),
            (
                "experimental_parallel_hack_factor = 0.0",
                "Invalid experimental_parallel_hack_factor of 0: must be between 0 and 1",
            ),
            (
                "experimental_parallel_hack_factor = -0.5",
                "Invalid experimental_parallel_hack_factor of -0.5: must be between 0 and 1",
            ),
            (
                "experimental_parallel_hack_factor = 1.5",
                "Invalid experimental_parallel_hack_factor of 1.5: must be between 0 and 1",
            ),
            (
                "experimental_parallel_hack_factor = nan",
                "Invalid experimental_parallel_hack_factor of NaN: must be between 0 and 1",
            ),
            (
                "experimental_parallel_hack_retryafter = 0",
                "Invalid experimental_parallel_hack_retryafter value of 0: must be between 1 and 300",
            ),
            (
                "experimental_parallel_hack_retryafter = 301",
                "Invalid experimental_parallel_hack_retryafter value of 301: must be between 1 and 300",
            ),
        ] {
            assert_eq!(error_for(input), expected, "input `{input}`");
        }
    }

    #[test]
    fn numeric_options_at_their_bounds_are_accepted() {
        for input in [
            "buffer_size = '1024'",
            "buffer_size = '1073741824'",
            "max_object_size = '1048576'",
            "byhash_retention_days = 213503982334601",
            "usage_retention_days = 213503982334601",
            "db_channel_capacity = 4096",
            "db_batch_flush_max_count = 4096",
            "db_batch_flush_interval_secs = 300",
            // Spelling out the default next to a disabled min_download_rate
            // must keep starting the daemon.
            "min_download_rate = '0'\nrate_check_timeframe = 30",
            "min_download_rate = '1000'\nrate_check_timeframe = 1",
            "min_download_rate = '1000'\nrate_check_timeframe = 360",
            "experimental_parallel_hack_factor = 0.001",
            "experimental_parallel_hack_factor = 1.0",
            "experimental_parallel_hack_retryafter = 1",
            "experimental_parallel_hack_retryafter = 300",
        ] {
            let mut cfg = Config::from_toml(input).expect("config parses");
            let result = cfg.validate();
            assert!(result.is_ok(), "input `{input}` must validate: {result:?}");
        }
    }

    #[test]
    fn timeouts_at_their_bounds_are_accepted() {
        let mut cfg = Config::from_toml(
            "database_slow_timeout = 60\n\
             http_timeout = 360\n\
             client_idle_timeout = 3600\n\
             upstream_retry_budget = 600",
        )
        .expect("config parses");
        cfg.validate().expect("boundary values are valid");
    }

    #[test]
    fn empty_path_options_are_rejected() {
        for (input, expected) in [
            ("log_file = ''", "Invalid log_file value: must not be empty"),
            (
                "cache_directory = ''",
                "Invalid cache_directory value: must not be empty",
            ),
            (
                "database_path = ''",
                "Invalid database_path value: must not be empty",
            ),
        ] {
            assert_eq!(error_for(input), expected, "input `{input}`");
        }
    }

    #[test]
    fn relative_path_options_warn_but_load() {
        let warnings = warnings_for(
            "log_file = 'relative.log'\n\
             cache_directory = 'cache'\n\
             database_path = 'db.sqlite'",
        );
        for key in ["log_file", "cache_directory", "database_path"] {
            assert!(
                warnings
                    .iter()
                    .any(|w| w.starts_with(&format!("{key} `"))
                        && w.contains("is not an absolute path")),
                "expected relative-path warning for {key}, got: {warnings:?}"
            );
        }
    }

    // -----------------------------------------------------------------
    // Alias-group conflicts
    // -----------------------------------------------------------------

    #[test]
    fn overlapping_alias_groups_are_rejected() {
        // Two groups that share any host would give one cache identity two
        // owners, so `validate` refuses the whole configuration.
        for (case, input) in [
            (
                "the same main twice",
                "aliases = [ ['deb.debian.org', ['a.debian.org']], ['deb.debian.org', ['b.debian.org']] ]",
            ),
            (
                "a later group aliases an earlier main",
                "aliases = [ ['deb.debian.org', ['a.debian.org']], ['b.debian.org', ['deb.debian.org']] ]",
            ),
            (
                "an earlier group aliases a later main",
                "aliases = [ ['deb.debian.org', ['b.debian.org']], ['b.debian.org', ['c.debian.org']] ]",
            ),
            (
                "both groups claim the same alias",
                "aliases = [ ['deb.debian.org', ['x.debian.org']], ['other.debian.org', ['x.debian.org']] ]",
            ),
        ] {
            let err = error_for(input);
            assert!(
                err.contains("conflicts with alias"),
                "{case} must be rejected, got: {err}"
            );
        }
    }

    #[test]
    fn disjoint_alias_groups_are_accepted_and_sorted() {
        let mut cfg = Config::from_toml(
            "aliases = [ ['deb.debian.org', ['ftp.us.debian.org', 'ftp.de.debian.org']], \
             ['archive.ubuntu.com', ['de.archive.ubuntu.com']] ]",
        )
        .expect("config parses");
        cfg.validate().expect("disjoint groups are valid");
        // `resolve_alias` binary-searches this list, so validation must
        // leave it sorted whatever order the operator wrote.
        let first = cfg.aliases.first().expect("two groups were configured");
        assert!(first.aliases.is_sorted(), "{:?}", first.aliases);
        let resolved =
            resolve_alias(&cfg.aliases, &clh("ftp.us.debian.org")).expect("alias resolves");
        assert_eq!(resolved.as_str(), "deb.debian.org");
    }

    // -----------------------------------------------------------------
    // Loading and CLI overrides
    // -----------------------------------------------------------------

    #[test]
    fn new_rejects_a_named_file_that_is_missing() {
        let dir = tempfile::tempdir().expect("tempdir");
        let err = Config::load(&dir.path().join("absent.conf"), None, None, None)
            .expect_err("an explicitly named file must exist");
        assert!(
            matches!(err, ConfigError::Read { .. }),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn new_applies_cli_overrides_on_top_of_the_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let file = dir.path().join("apt-cacher-rs.conf");
        std::fs::write(
            &file,
            "bind_port = 3143\ncache_directory = '/srv/from-file'\n",
        )
        .expect("write config");

        let loaded = Config::load(&file, None, None, None).expect("config loads");
        assert!(
            !loaded.defaults_used,
            "a file that exists is not the built-in fallback"
        );
        assert_eq!(loaded.config.bind_port, nonzero!(3143_u16));
        assert_eq!(
            loaded.config.cache_directory,
            PathBuf::from("/srv/from-file")
        );

        let loaded = Config::load(
            &file,
            Some(PathBuf::from("/srv/from-cli")),
            Some(PathBuf::from("/srv/from-cli.db")),
            Some(bind("127.0.0.1:3199")),
        )
        .expect("config loads");
        assert_eq!(
            loaded.config.cache_directory,
            PathBuf::from("/srv/from-cli")
        );
        assert_eq!(
            loaded.config.database_path,
            PathBuf::from("/srv/from-cli.db")
        );
        assert_eq!(loaded.config.bind_addr, IpAddr::from(Ipv4Addr::LOCALHOST));
        assert_eq!(loaded.config.bind_port, nonzero!(3199_u16));
    }
}
