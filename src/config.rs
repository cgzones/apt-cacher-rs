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
//! still gets the warning. Feature-gated options mirror `mmap_threshold`.
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

/// Default of [`Config::rate_check_timeframe`]; a named const (not a field of
/// `Config::default()`) because `ringbuffer.rs` pins its inline capacity to it
/// in a `static_assert!`.
pub(crate) const DEFAULT_RATE_CHECK_TIMEFRAME: NonZero<usize> = nonzero!(30);

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
pub(crate) enum HttpsUpgradeMode {
    Auto,
    Always,
    Never,
}

#[derive(Debug, PartialEq, Eq)]
enum ConfigDomainNameInner {
    Dns(String),
    Ipv4(String, Ipv4Addr),
    Ipv6(String, Ipv6Addr),
    Wildcard(String),
}

/// An allow-list *pattern*, which may be a wildcard and so has no useful
/// ordering: the lists it populates (`allowed_mirrors`, `http_only_mirrors`)
/// are always scanned with [`Self::permits`], never sorted or searched.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ConfigDomainName(ConfigDomainNameInner);

impl ConfigDomainName {
    pub(crate) fn new(domain: String) -> Result<Self, String> {
        if !is_valid_config_domain(&domain) {
            return Err(domain);
        }

        // DNS names are case-insensitive: normalise so `DEB.debian.org` and
        // `deb.debian.org` are one allow-list entry, one cache tree and one
        // mirror row.
        if let Some(d) = domain.strip_prefix('*') {
            return Ok(Self(ConfigDomainNameInner::Wildcard(
                d.to_ascii_lowercase(),
            )));
        }

        if domain.contains(':') {
            return domain
                .parse::<Ipv6Addr>()
                .map(|addr| Self(ConfigDomainNameInner::Ipv6(addr.to_string(), addr)))
                .map_err(|_parse_err| domain);
        }

        if let Ok(addr) = domain.parse::<Ipv4Addr>() {
            return Ok(Self(ConfigDomainNameInner::Ipv4(addr.to_string(), addr)));
        }

        Ok(Self(ConfigDomainNameInner::Dns(
            domain.to_ascii_lowercase(),
        )))
    }

    #[must_use]
    #[inline]
    pub(crate) const fn as_str(&self) -> Option<&str> {
        match self {
            Self(
                ConfigDomainNameInner::Dns(s)
                | ConfigDomainNameInner::Ipv4(s, _)
                | ConfigDomainNameInner::Ipv6(s, _),
            ) => Some(s.as_str()),
            Self(ConfigDomainNameInner::Wildcard(_)) => None,
        }
    }

    #[must_use]
    pub(crate) fn permits(&self, domain: &str) -> bool {
        match self {
            Self(ConfigDomainNameInner::Wildcard(d)) => domain.ends_with(d),
            Self(ConfigDomainNameInner::Dns(d)) => domain == d,
            Self(ConfigDomainNameInner::Ipv4(s, a)) => {
                domain == s || domain.parse::<Ipv4Addr>().is_ok_and(|d| d == *a)
            }
            Self(ConfigDomainNameInner::Ipv6(s, a)) => {
                domain == s || domain.parse::<Ipv6Addr>().is_ok_and(|d| d == *a)
            }
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

        Self::new(s).map_err(|s| D::Error::custom(format!("Invalid configuration domain `{s}`")))
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

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub(crate) struct DomainName(DomainNameInner);

impl DomainName {
    pub(crate) fn new(domain: String) -> Result<Self, String> {
        if domain.contains(':') {
            return domain
                .parse::<Ipv6Addr>()
                .map(|addr| Self(DomainNameInner::Ipv6(addr.to_string().into(), addr)))
                .map_err(|_parse_err| domain);
        }

        if let Ok(addr) = domain.parse::<Ipv4Addr>() {
            return Ok(Self(DomainNameInner::Ipv4(addr.to_string().into(), addr)));
        }

        // At this point we've already proven there's no `:` and the string
        // is not a valid IPv4 address, so skip those branches in the
        // validator.
        if is_valid_dns_label_string(&domain) {
            // DNS names are case-insensitive: one cache tree, mirror row and
            // registry scope per host, whatever case the client typed.
            Ok(Self(DomainNameInner::Dns(
                domain.to_ascii_lowercase().into(),
            )))
        } else {
            Err(domain)
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
    #[must_use]
    pub(crate) fn format_authority(&self, port: Option<NonZero<u16>>) -> Cow<'_, str> {
        match (self.is_ipv6(), port) {
            (true, Some(port)) => Cow::Owned(format!("[{self}]:{port}")),
            (true, None) => Cow::Owned(format!("[{self}]")),
            (false, Some(port)) => Cow::Owned(format!("{self}:{port}")),
            (false, None) => Cow::Borrowed(self.as_str()),
        }
    }

    /// Format as a cache directory name component.
    ///
    /// Unlike [`format_authority`](Self::format_authority), IPv6 addresses
    /// are **not** bracketed - the bare address is used as a directory name.
    #[must_use]
    pub(crate) fn format_cache_dir(&self, port: Option<NonZero<u16>>) -> Cow<'_, str> {
        match port {
            Some(port) => Cow::Owned(format!("{self}:{port}")),
            None => Cow::Borrowed(self.as_str()),
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

impl std::fmt::Display for DomainName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.as_str().fmt(f)
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

        Self::new(s).map_err(|s| D::Error::custom(format!("Invalid domain `{s}`")))
    }
}

impl AsRef<std::ffi::OsStr> for DomainName {
    fn as_ref(&self) -> &std::ffi::OsStr {
        self.as_str().as_ref()
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
        Self::new(s).map_err(|s| format!("Invalid domain in database: {s}").into())
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
    /// Returns an error if the string is not a valid domain name.
    pub(crate) fn new(host: String) -> Result<Self, String> {
        Ok(Self(DomainName::new(host)?))
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

impl AsRef<std::ffi::OsStr> for ClientHost {
    fn as_ref(&self) -> &std::ffi::OsStr {
        self.0.as_ref()
    }
}

impl AsRef<std::ffi::OsStr> for CacheHost {
    fn as_ref(&self) -> &std::ffi::OsStr {
        self.0.as_ref()
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

#[derive(Debug, Deserialize, PartialEq)]
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

#[derive(Debug, PartialEq)]
pub(crate) enum IpNetOrAddr {
    Net(IpNet),
    Addr(IpAddr),
}

impl IpNetOrAddr {
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
            return Ok(Self::Addr(ip));
        }

        s.parse::<IpNet>()
            .map(IpNetOrAddr::Net)
            .map_err(D::Error::custom)
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
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

    /// Address to listen on.
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

    /// Disk quota (in bytes) for cache.
    #[serde(deserialize_with = "from_nonzero_u64_with_magnitude")]
    pub(crate) disk_quota: Option<NonZero<u64>>,

    /// Minimum free disk space (in bytes) on the cache filesystem for the
    /// `/healthcheck` endpoint to report healthy. `None` (config value `0`)
    /// disables the check.
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

    /// List of mirrors supporting only http.
    pub(crate) http_only_mirrors: Vec<ConfigDomainName>,

    /// List of clients permitted to use the proxy.
    /// Empty means all clients are allowed.
    pub(crate) allowed_proxy_clients: Vec<IpNetOrAddr>,

    /// List of clients permitted to use the web-interface.
    /// Empty means all clients are allowed.
    /// None means setting is inherited from `allowed_proxy_clients`.
    pub(crate) allowed_webif_clients: Option<Vec<IpNetOrAddr>>,

    /// Whether https tunneling (`CONNECT`) is enabled.  Off by default: a
    /// tunnel is an open TCP relay to every host in
    /// [`Self::https_tunnel_allowed_mirrors`], so it is enabled together
    /// with that list.
    pub(crate) https_tunnel_enabled: bool,

    /// Allowed ports for https tunneling.
    pub(crate) https_tunnel_allowed_ports: Vec<NonZero<u16>>,

    /// Allowed mirrors for https tunneling.  Fail-closed like
    /// [`Self::allowed_mirrors`]: an empty list permits no CONNECT target.
    pub(crate) https_tunnel_allowed_mirrors: Vec<DomainName>,

    /// Maximum number of concurrent HTTPS tunnel connections per client IP.
    /// `None` means unlimited.
    #[serde(deserialize_with = "from_nonzero_usize")]
    pub(crate) https_tunnel_max_connections_per_client: Option<NonZero<usize>>,

    /// Maximum number of concurrent plain-HTTP connections accepted per source
    /// IP address. `None` means unlimited. Set to bound resource use against
    /// half-open connection floods on deployments exposed to less-trusted
    /// networks. Note: clients behind a NAT share a single IP for this cap.
    #[serde(deserialize_with = "from_nonzero_usize")]
    pub(crate) max_connections_per_client_ip: Option<NonZero<usize>>,

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

    /// Capacity of the internal database command channel.
    pub(crate) db_channel_capacity: NonZero<usize>,

    /// Maximum number of pending database events buffered before a batch flush.
    pub(crate) db_batch_flush_max_count: NonZero<usize>,

    /// Interval (in seconds) between database batch flushes and mirror
    /// `last_seen` syncs.
    pub(crate) db_batch_flush_interval_secs: NonZero<u64>,

    /// Threshold (in bytes) for using memory-mapped files for large downloads.
    pub(crate) mmap_threshold: NonZero<u64>,

    /// Whether to pin the kTLS handshake buffers (which hold TLS secrets and
    /// decrypted handshake data) in RAM via `mlock(2)`, keeping them out of
    /// swap. Disable in mlock-restricted environments (containers, tight
    /// `RLIMIT_MEMLOCK`). Zeroize-on-drop and core-dump exclusion stay
    /// active regardless.
    pub(crate) ktls_memory_lock: bool,

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
            http_only_mirrors: Vec::new(),
            allowed_proxy_clients: Vec::new(),
            allowed_webif_clients: None,
            https_tunnel_enabled: false,
            https_tunnel_allowed_ports: vec![nonzero!(443)],
            https_tunnel_allowed_mirrors: Vec::new(),
            https_tunnel_max_connections_per_client: Some(nonzero!(10)),
            max_connections_per_client_ip: None,
            max_connections: Some(client_counter::default_max_connections()),
            min_download_rate: Some(nonzero!(10000)), // 10 kB/s
            rate_check_timeframe: DEFAULT_RATE_CHECK_TIMEFRAME,
            max_upstream_downloads: Some(nonzero!(20)),
            db_channel_capacity: nonzero!(128),
            db_batch_flush_max_count: nonzero!(256),
            db_batch_flush_interval_secs: nonzero!(15),
            mmap_threshold: nonzero!(1024 * 1024), // 1 MiB
            ktls_memory_lock: true,
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

/// Validator for an allow-list entry: a bare IPv6 address, a DNS name (or
/// IPv4 address, which is a valid label string), or a name carrying a
/// leading `*.` wildcard label.
///
/// A wildcard must cover at least two further labels — `*.org` would hand
/// a whole TLD to the proxy — and must not look like a partial IPv4
/// address (`*.1.1`), which no `Ipv4Addr`-normalised lookup could ever
/// match.  Everything past the wildcard is the plain DNS label rule, so it
/// is checked by [`is_valid_dns_label_string`].
#[must_use]
fn is_valid_config_domain(domain: &str) -> bool {
    /* No unicode characters allowed for now */

    if domain.is_empty() || domain.len() > 253 {
        return false;
    }

    // IPv6 addresses contain colons; wildcards don't apply to them
    if domain.contains(':') {
        return domain.parse::<Ipv6Addr>().is_ok();
    }

    let Some(suffix) = domain.strip_prefix("*.") else {
        return is_valid_dns_label_string(domain);
    };

    suffix.contains('.')
        && is_valid_dns_label_string(suffix)
        && !suffix.split('.').all(|part| part.parse::<u8>().is_ok())
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
    /// (see [`Self::is_set`]) before deserializing it.
    ///
    /// Parses to a spanned table first so unknown-key and type errors keep
    /// their line/column information.
    fn from_toml(content: &str) -> Result<Self, toml::de::Error> {
        let table = toml::de::DeTable::parse(content)?;
        let present = table
            .get_ref()
            .keys()
            .map(|key| key.get_ref().to_string())
            .collect();
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

            if max_object_size < self.mmap_threshold {
                warnings.push(format!(
                    "max_object_size of {} is smaller than mmap_threshold ({}); accepted downloads will always stay below the mmap threshold, so the mmap delivery path will never be exercised",
                    max_object_size.get(),
                    self.mmap_threshold.get()
                ));
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

        self.https_tunnel_allowed_ports.sort_unstable();
        self.https_tunnel_allowed_mirrors.sort_unstable();

        if !self.allowed_mirrors.is_empty() {
            for mirror in &self.http_only_mirrors {
                let Some(mirror_str) = mirror.as_str() else {
                    continue;
                };

                if !self.allowed_mirrors.iter().any(|a| a.permits(mirror_str)) {
                    warnings.push(format!(
                        "http_only_mirrors entry `{mirror_str}` is not permitted by allowed_mirrors"
                    ));
                }
            }
        }

        if self.https_tunnel_enabled && !self.allowed_mirrors.is_empty() {
            for mirror in &self.https_tunnel_allowed_mirrors {
                if !self
                    .allowed_mirrors
                    .iter()
                    .any(|a| a.permits(mirror.as_str()))
                {
                    warnings.push(format!(
                        "https_tunnel_allowed_mirrors entry `{mirror}` is not permitted by allowed_mirrors"
                    ));
                }
            }
        }

        if !self.allowed_mirrors.is_empty() {
            for alias in &self.aliases {
                if !self
                    .allowed_mirrors
                    .iter()
                    .any(|a| a.permits(alias.main.as_str()))
                {
                    warnings.push(format!(
                        "alias target `{}` is not permitted by allowed_mirrors",
                        alias.main
                    ));
                }
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

        #[cfg(not(feature = "mmap"))]
        if self.is_set("mmap_threshold") {
            warnings.push(format!(
                "mmap_threshold is set to {} but mmap feature is not enabled",
                self.mmap_threshold
            ));
        }

        #[cfg(not(feature = "ktls"))]
        if self.is_set("ktls_memory_lock") {
            warnings.push("ktls_memory_lock is set but ktls feature is not enabled".to_owned());
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
            DomainName::new(s.to_owned()).is_ok()
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

    #[test]
    fn test_is_valid_config_domain() {
        assert!(is_valid_config_domain("debian.org"));

        assert!(is_valid_config_domain("salsa.debian.org"));

        assert!(is_valid_config_domain("metadata.ftp-master.debian.org"));

        // empty
        assert!(!is_valid_config_domain(""));

        // double dots
        assert!(!is_valid_config_domain("debian..org"));

        // short part
        assert!(is_valid_config_domain("debian.f.org"));

        // too long part
        assert!(!is_valid_config_domain(
            "debian.abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789AAA.org"
        ));

        // starting dash
        assert!(!is_valid_config_domain("-debian.org"));

        // ending dash
        assert!(!is_valid_config_domain("debian-.org"));

        // dash in position 2
        assert!(is_valid_config_domain("d-ebian.org"));

        // dash in position 3
        assert!(is_valid_config_domain("de-bian.org"));

        // dash in position 4
        assert!(is_valid_config_domain("deb-ian.org"));

        // dash in position 5
        assert!(is_valid_config_domain("debi-an.org"));

        // invalid char
        assert!(!is_valid_config_domain("deb_ian.org"));

        // special directory entry
        assert!(!is_valid_config_domain("."));
        assert!(!is_valid_config_domain(".."));
        assert!(!is_valid_config_domain("foo/bar"));

        // wild card
        assert!(is_valid_config_domain("*.debian.org"));
        assert!(!is_valid_config_domain("*e.debian.org"));
        assert!(!is_valid_config_domain("deb.*.debian.org"));
        assert!(!is_valid_config_domain("debian.*"));

        // wildcard minimum depth (must have at least 3 parts)
        assert!(!is_valid_config_domain("*.org"));
        assert!(!is_valid_config_domain("*.com"));
        assert!(is_valid_config_domain("*.debian.org"));
        assert!(is_valid_config_domain("*.ftp.debian.org"));

        // a wildcard is the whole first label and nothing else
        assert!(!is_valid_config_domain("*"));
        assert!(!is_valid_config_domain("*."));
        assert!(!is_valid_config_domain("**.debian.org"));
        assert!(!is_valid_config_domain("*-.debian.org"));
        assert!(!is_valid_config_domain("*.debian.org."));

        // IPv4 addresses
        assert!(is_valid_config_domain("192.168.1.1"));
        assert!(is_valid_config_domain("10.0.0.1"));
        assert!(is_valid_config_domain("127.0.0.1"));
        assert!(is_valid_config_domain("255.255.255.255"));

        // IPv6 addresses
        assert!(is_valid_config_domain("::1"));
        assert!(is_valid_config_domain("2001:db8::1"));
        assert!(is_valid_config_domain("fe80::1"));
        assert!(is_valid_config_domain("::ffff:192.168.1.1"));
        assert!(is_valid_config_domain(
            "2001:0db8:0000:0000:0000:0000:0000:0001"
        ));

        // invalid IPv6
        assert!(!is_valid_config_domain(":::1"));
        assert!(!is_valid_config_domain("2001:db8::xyz"));
        assert!(!is_valid_config_domain("2001:db8::1::2"));

        // Wildcards that look like partial IPv4 addresses
        assert!(!is_valid_config_domain("*.1.1"));
        assert!(!is_valid_config_domain("*.168.1.1"));
        assert!(!is_valid_config_domain("*.0.0.1"));
    }

    // -----------------------------------------------------------------
    // Alias resolution + host-wrapper helpers
    // -----------------------------------------------------------------

    fn dn(s: &str) -> DomainName {
        DomainName::new(s.to_owned()).expect("test input must be a valid domain")
    }

    fn clh(s: &str) -> ClientHost {
        ClientHost::new(s.to_owned()).expect("test input must be a valid domain")
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
        let host = DomainName::new("DEB.Debian.ORG".to_owned()).expect("valid");
        assert_eq!(host.as_str(), "deb.debian.org");
        let exact = ConfigDomainName::new("Deb.debian.org".to_owned()).expect("valid");
        assert!(exact.permits("deb.debian.org"));
        assert_eq!(exact.as_str(), Some("deb.debian.org"));
        let wildcard = ConfigDomainName::new("*.Debian.ORG".to_owned()).expect("valid");
        assert!(wildcard.permits("deb.debian.org"));
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
        // relies on for `as_str` / `format_cache_dir` / `format_authority`.
        let client = clh("example.test");
        let cache = cah("example.test");
        let port = NonZero::new(8080);
        assert_eq!(client.format_cache_dir(port).as_ref(), "example.test:8080");
        assert_eq!(cache.format_cache_dir(port).as_ref(), "example.test:8080");
        assert_eq!(client.format_authority(port).as_ref(), "example.test:8080");
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
        assert!(!cfg.is_set("mmap_threshold"));
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

    #[test]
    fn mmap_threshold_set_warns_only_without_mmap_feature() {
        let warnings = warnings_for("mmap_threshold = 1048576");
        let warned = warnings
            .iter()
            .any(|w| w == "mmap_threshold is set to 1048576 but mmap feature is not enabled");
        assert_eq!(
            warned,
            !cfg!(feature = "mmap"),
            "mmap_threshold warning must track the mmap feature: {warnings:?}"
        );
        assert!(
            !warnings_for("")
                .iter()
                .any(|w| w.contains("mmap feature is not enabled")),
            "unset mmap_threshold must not warn"
        );
    }

    #[test]
    fn ktls_memory_lock_set_warns_only_without_ktls_feature() {
        for line in ["ktls_memory_lock = true", "ktls_memory_lock = false"] {
            let warnings = warnings_for(line);
            let warned = warnings
                .iter()
                .any(|w| w == "ktls_memory_lock is set but ktls feature is not enabled");
            assert_eq!(
                warned,
                !cfg!(feature = "ktls"),
                "ktls_memory_lock warning must track the ktls feature for `{line}`: {warnings:?}"
            );
        }
        assert!(
            !warnings_for("")
                .iter()
                .any(|w| w.contains("ktls feature is not enabled")),
            "unset ktls_memory_lock must not warn"
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
