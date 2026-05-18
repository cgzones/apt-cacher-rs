use std::borrow::Cow;
use std::cmp::Ordering;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::num::NonZero;
use std::path::Path;
use std::path::PathBuf;
use std::str::FromStr as _;
use std::time::Duration;

use anyhow::Context as _;
use anyhow::anyhow;
use anyhow::bail;
use ipnet::IpNet;
use log::LevelFilter;
use serde::Deserialize;
use serde::Deserializer;

use crate::VOLATILE_UNKNOWN_CONTENT_LENGTH_UPPER;
use crate::nonzero;

const DEFAULT_CACHE_DIR: &str = "/var/cache/apt-cacher-rs";
pub(crate) const DEFAULT_CONFIGURATION_PATH: &str = "/etc/apt-cacher-rs/apt-cacher-rs.conf";
pub(crate) const DEFAULT_DATABASE_PATH: &str = "/var/lib/apt-cacher-rs/apt-cacher-rs.db";

const DEFAULT_BIND_ADDRESS: IpAddr = IpAddr::V6(Ipv6Addr::UNSPECIFIED);
const DEFAULT_BIND_PORT: NonZero<u16> = nonzero!(3142);
const DEFAULT_BUF_SIZE: usize = 32 * 1024; // 32 KiB
const DEFAULT_DATABASE_SLOW_TIMEOUT: Duration = Duration::from_secs(2);
const DEFAULT_DISK_QUOTA: Option<NonZero<u64>> = None;
const DEFAULT_HTTP_TIMEOUT: Duration = Duration::from_secs(10);
const DEFAULT_CLIENT_IDLE_TIMEOUT: Duration = Duration::from_mins(2);
const DEFAULT_HTTPS_UPGRADE_MODE: HttpsUpgradeMode = HttpsUpgradeMode::Auto;
const DEFAULT_HTTPS_TUNNEL_ENABLED: bool = true;
const DEFAULT_HTTPS_TUNNEL_ALLOWED_PORTS: [NonZero<u16>; 1] = [nonzero!(443)];
const DEFAULT_HTTPS_TUNNEL_MAX_CONNECTIONS_PER_CLIENT: Option<NonZero<usize>> = Some(nonzero!(10));
const DEFAULT_MAX_CONNECTIONS_PER_CLIENT_IP: Option<NonZero<usize>> = None;
const DEFAULT_LOG_LEVEL: LevelFilter = LevelFilter::Info;
const DEFAULT_LOG_DESTINATION: LogDestination = LogDestination::Console;
const DEFAULT_LOGSTORE_CAPACITY: NonZero<usize> = nonzero!(100);
const DEFAULT_MIN_DOWNLOAD_RATE: Option<NonZero<usize>> = Some(nonzero!(10000)); // 10 kB/s
pub(crate) const DEFAULT_RATE_CHECK_TIMEFRAME: NonZero<usize> = nonzero!(30);
const DEFAULT_MAX_UPSTREAM_DOWNLOADS: Option<NonZero<usize>> = Some(nonzero!(20));
const DEFAULT_BYHASH_RETENTION_DAYS: NonZero<u64> = nonzero!(90);
const DEFAULT_USAGE_RETENTION_DAYS: Option<NonZero<u64>> = Some(nonzero!(30));
const DEFAULT_DB_CHANNEL_CAPACITY: NonZero<usize> = nonzero!(128);
const DEFAULT_DB_BATCH_FLUSH_MAX_COUNT: NonZero<usize> = nonzero!(256);
const DEFAULT_DB_BATCH_FLUSH_INTERVAL_SECS: NonZero<u64> = nonzero!(15);
const DEFAULT_MMAP_THRESHOLD: NonZero<u64> = nonzero!(1024 * 1024); // 1MiB
const DEFAULT_MAX_OBJECT_SIZE: Option<NonZero<u64>> = Some(nonzero!(2 * 1024 * 1024 * 1024));
const DEFAULT_UPSTREAM_TCP_NODELAY: bool = true;
const DEFAULT_REJECT_PDIFF_REQUESTS: bool = true;
const DEFAULT_EXPERIMENTAL_PARALLEL_HACK_ENABLED: bool = false;
const DEFAULT_EXPERIMENTAL_PARALLEL_HACK_MAXPARALLEL: Option<NonZero<usize>> = Some(nonzero!(3));
const DEFAULT_EXPERIMENTAL_PARALLEL_HACK_STATUSCODE: hyper::StatusCode =
    hyper::StatusCode::TOO_MANY_REQUESTS;
const DEFAULT_EXPERIMENTAL_PARALLEL_HACK_RETRYAFTER: u16 = 5;
const DEFAULT_EXPERIMENTAL_PARALLEL_HACK_FACTOR: f64 = 0.2;
const DEFAULT_EXPERIMENTAL_PARALLEL_HACK_MINSIZE: Option<NonZero<u64>> =
    Some(nonzero!(10 * 1024 * 1024)); // 10 MiB

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
pub(crate) enum HttpsUpgradeMode {
    Auto,
    Always,
    Never,
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
enum ConfigDomainNameInner {
    Dns(String),
    Ipv4(String, Ipv4Addr),
    Ipv6(String, Ipv6Addr),
    Wildcard(String),
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct ConfigDomainName(ConfigDomainNameInner);

impl ConfigDomainName {
    pub(crate) fn new(domain: String) -> Result<Self, String> {
        if !is_valid_config_domain(&domain) {
            return Err(domain);
        }

        if let Some(d) = domain.strip_prefix('*') {
            return Ok(Self(ConfigDomainNameInner::Wildcard(d.to_string())));
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

        Ok(Self(ConfigDomainNameInner::Dns(domain)))
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

        Self::new(s)
            .map_err(|s| anyhow!("Invalid configuration domain `{s}`"))
            .map_err(D::Error::custom)
    }
}

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
enum DomainNameInner {
    Dns(String),
    Ipv4(String, Ipv4Addr),
    Ipv6(String, Ipv6Addr),
}

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub(crate) struct DomainName(DomainNameInner);

impl DomainName {
    pub(crate) fn new(domain: String) -> Result<Self, String> {
        if domain.contains(':') {
            return domain
                .parse::<Ipv6Addr>()
                .map(|addr| Self(DomainNameInner::Ipv6(addr.to_string(), addr)))
                .map_err(|_parse_err| domain);
        }

        if let Ok(addr) = domain.parse::<Ipv4Addr>() {
            return Ok(Self(DomainNameInner::Ipv4(addr.to_string(), addr)));
        }

        // At this point we've already proven there's no `:` and the string
        // is not a valid IPv4 address, so skip those branches in the
        // validator.
        if is_valid_dns_label_string(&domain) {
            Ok(Self(DomainNameInner::Dns(domain)))
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
    pub(crate) const fn as_str(&self) -> &str {
        match self {
            Self(
                DomainNameInner::Dns(s) | DomainNameInner::Ipv4(s, _) | DomainNameInner::Ipv6(s, _),
            ) => s.as_str(),
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

        Self::new(s)
            .map_err(|s| anyhow!("Invalid domain `{s}`"))
            .map_err(D::Error::custom)
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
            ) => s,
        }
    }
}

impl<'a> From<&'a DomainName> for &'a String {
    fn from(val: &'a DomainName) -> Self {
        match val {
            DomainName(
                DomainNameInner::Dns(s) | DomainNameInner::Ipv4(s, _) | DomainNameInner::Ipv6(s, _),
            ) => s,
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
        buf: &mut <sqlx::Sqlite as sqlx::Database>::ArgumentBuffer<'q>,
    ) -> Result<sqlx::encode::IsNull, sqlx::error::BoxDynError> {
        <String as sqlx::Encode<'q, sqlx::Sqlite>>::encode_by_ref(self.into(), buf)
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
// * [`ClientHost`] — the host the client put on the wire (post-validation).
//   Used verbatim for the upstream TCP/TLS connect, the outgoing `Host:`
//   header, the DB primary key on `mirrors_v2`, and origin lookups.
// * [`CacheHost`]  — the alias-resolved on-disk identity.  Used for the
//   per-host cache directory, the flat-collision blocklist, and the
//   cleanup/scan filesystem traversal.
//
// Both wrap a validated [`DomainName`] and carry the same byte content when
// no alias maps the client name.  Keeping them as distinct types prevents
// callers from accidentally handing a resolved name to a function that
// expects a raw one (and vice versa) — the invariant used to rest on
// careful variable naming alone.
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
            std::mem::size_of::<ClientHost>() == std::mem::size_of::<CacheHost>()
                && std::mem::align_of::<ClientHost>() == std::mem::align_of::<CacheHost>(),
            "ClientHost and CacheHost must share layout - one of them lost its #[repr(transparent)] or gained a second field",
        );
        // `transmute` is well-typed only when both sides share an
        // identical layout, so this additionally catches a regression
        // that changes the inner field type of either wrapper to
        // something that happens to be the same width as `DomainName`
        // (size_of + align_of alone would not flag that).
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
        buf: &mut <sqlx::Sqlite as sqlx::Database>::ArgumentBuffer<'q>,
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

#[derive(Debug, Deserialize)]
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
/// `aliases[].aliases` is sorted at config load (see `Config::new`),
/// so the inner lookup is a binary search.
#[must_use]
pub(crate) fn resolve_alias<'a>(aliases: &'a [Alias], host: &ClientHost) -> Option<&'a CacheHost> {
    aliases
        .iter()
        .find(|alias| alias.aliases.binary_search(host).is_ok())
        .map(|alias| &alias.main)
}

#[derive(Debug)]
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

#[derive(Clone, Debug, Deserialize)]
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

#[expect(clippy::struct_excessive_bools, reason = "configuration")]
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Config {
    /// Minimum log level severity to output.
    /// Can be overridden via program options.
    #[serde(default = "default_log_level", deserialize_with = "from_level_name")]
    pub(crate) log_level: LevelFilter,

    /// Path to log file.
    /// The special value `console` will output to the console.
    /// Can be overridden via program options.
    #[serde(default = "default_log_file")]
    pub(crate) log_file: LogDestination,

    /// Address to listen on.
    #[serde(default = "default_bind_addr")]
    pub(crate) bind_addr: IpAddr,

    /// Port to listen on.
    #[serde(default = "default_bind_port")]
    pub(crate) bind_port: NonZero<u16>,

    /// Path to database.
    #[serde(default = "default_database_path")]
    pub(crate) database_path: PathBuf,

    /// Path to cache directory.
    #[serde(default = "default_cache_dir")]
    pub(crate) cache_directory: PathBuf,

    /// Timeout (in seconds) of database operations after which a warning is generated.
    #[serde(
        default = "default_db_slow_timeout",
        deserialize_with = "from_secs_f64"
    )]
    pub(crate) database_slow_timeout: Duration,

    /// Timeout (in seconds) for http operations.
    #[serde(default = "default_http_timeout", deserialize_with = "from_secs_f64")]
    pub(crate) http_timeout: Duration,

    /// Timeout (in seconds) after which an inbound client connection is closed
    /// while waiting for a complete HTTP request -- covers idle keep-alive
    /// connections and slowloris-style partial header sends.
    #[serde(
        default = "default_client_idle_timeout",
        deserialize_with = "from_secs_f64"
    )]
    pub(crate) client_idle_timeout: Duration,

    /// HTTPS upgrade mode.
    #[serde(default = "default_https_upgrade_mode")]
    pub(crate) https_upgrade_mode: HttpsUpgradeMode,

    /// Size (in bytes) of buffer used for internal data transfer.
    #[serde(
        default = "default_buffer_size",
        deserialize_with = "from_usize_with_magnitude"
    )]
    pub(crate) buffer_size: usize,

    /// Number of stored error and warning log messages.
    #[serde(default = "default_logstore_capacity")]
    pub(crate) logstore_capacity: NonZero<usize>,

    /// Disk quota (in bytes) for cache.
    #[serde(
        default = "default_disk_quota",
        deserialize_with = "from_nonzero_u64_with_magnitude"
    )]
    pub(crate) disk_quota: Option<NonZero<u64>>,

    /// Maximum size (in bytes) of a single upstream object that will be
    /// downloaded and cached. An upstream response declaring a larger
    /// Content-Length is rejected with 502 Bad Gateway before any bytes are
    /// stored. Set to `0` to disable the cap.
    #[serde(
        default = "default_max_object_size",
        deserialize_with = "from_nonzero_u64_with_magnitude"
    )]
    pub(crate) max_object_size: Option<NonZero<u64>>,

    /// Retention time (in days) for files acquired "by-hash".
    #[serde(default = "default_byhash_retention_days")]
    pub(crate) byhash_retention_days: NonZero<u64>,

    /// Retention time (in days) for usage logs.
    #[serde(
        default = "default_usage_retention_days",
        deserialize_with = "from_nonzero_u64"
    )]
    pub(crate) usage_retention_days: Option<NonZero<u64>>,

    /// Mirror aliases.
    #[serde(default = "default_aliases")]
    pub(crate) aliases: Vec<Alias>,

    /// List of allowed mirrors.
    #[serde(default = "default_allowed_mirrors")]
    pub(crate) allowed_mirrors: Vec<ConfigDomainName>,

    /// List of mirrors supporting only http.
    #[serde(default = "default_http_only_mirrors")]
    pub(crate) http_only_mirrors: Vec<ConfigDomainName>,

    /// List of clients permitted to use the proxy.
    /// Empty means all clients are allowed.
    #[serde(default = "default_allowed_proxy_clients")]
    pub(crate) allowed_proxy_clients: Vec<IpNetOrAddr>,

    /// List of clients permitted to use the web-interface.
    /// Empty means all clients are allowed.
    /// None means setting is inherited from `allowed_proxy_clients`.
    #[serde(default = "default_allowed_webif_clients")]
    pub(crate) allowed_webif_clients: Option<Vec<IpNetOrAddr>>,

    /// Whether https tunneling is enabled.
    #[serde(default = "default_https_tunnel_enabled")]
    pub(crate) https_tunnel_enabled: bool,

    /// Allowed ports for https tunneling.
    #[serde(default = "default_https_tunnel_allowed_ports")]
    pub(crate) https_tunnel_allowed_ports: Vec<NonZero<u16>>,

    /// Allowed mirrors for https tunneling.
    #[serde(default = "default_https_tunnel_allowed_mirrors")]
    pub(crate) https_tunnel_allowed_mirrors: Vec<DomainName>,

    /// Maximum number of concurrent HTTPS tunnel connections per client IP.
    /// `None` means unlimited.
    #[serde(
        default = "default_https_tunnel_max_connections_per_client",
        deserialize_with = "from_nonzero_usize"
    )]
    pub(crate) https_tunnel_max_connections_per_client: Option<NonZero<usize>>,

    /// Maximum number of concurrent plain-HTTP connections accepted per source
    /// IP address. `None` means unlimited. Set to bound resource use against
    /// half-open connection floods on deployments exposed to less-trusted
    /// networks. Note: clients behind a NAT share a single IP for this cap.
    #[serde(
        default = "default_max_connections_per_client_ip",
        deserialize_with = "from_nonzero_usize"
    )]
    pub(crate) max_connections_per_client_ip: Option<NonZero<usize>>,

    /// Minimum transfer rate (in bytes per second) for downloads and uploads.
    /// Connections that fail to fulfill this limit are cancelled.
    #[serde(
        default = "default_min_download_rate",
        deserialize_with = "from_nonzero_usize_with_magnitude"
    )]
    pub(crate) min_download_rate: Option<NonZero<usize>>,

    /// Sliding window (in seconds) over which the minimum transfer rate is measured.
    #[serde(default = "default_rate_check_timeframe")]
    pub(crate) rate_check_timeframe: NonZero<usize>,

    /// Maximum number of concurrent upstream downloads.
    /// `None` means unlimited.
    #[serde(
        default = "default_max_upstream_downloads",
        deserialize_with = "from_nonzero_usize"
    )]
    pub(crate) max_upstream_downloads: Option<NonZero<usize>>,

    /// Capacity of the internal database command channel.
    #[serde(default = "default_db_channel_capacity")]
    pub(crate) db_channel_capacity: NonZero<usize>,

    /// Maximum number of pending database events buffered before a batch flush.
    #[serde(default = "default_db_batch_flush_max_count")]
    pub(crate) db_batch_flush_max_count: NonZero<usize>,

    /// Interval (in seconds) between database batch flushes and mirror
    /// `last_seen` syncs.
    #[serde(default = "default_db_batch_flush_interval_secs")]
    pub(crate) db_batch_flush_interval_secs: NonZero<u64>,

    /// Threshold (in bytes) for using memory-mapped files for large downloads.
    #[serde(default = "default_mmap_threshold")]
    pub(crate) mmap_threshold: NonZero<u64>,

    /// Whether to set `TCP_NODELAY` on upstream sockets (hyper, splice, and
    /// CONNECT tunnels).  Mirror requests are typically a small header
    /// followed by a long body read; disabling Nagle's algorithm avoids the
    /// 40 ms ACK delay the kernel can otherwise add to every request.
    #[serde(default = "default_upstream_tcp_nodelay")]
    pub(crate) upstream_tcp_nodelay: bool,

    /// Whether to reject differential (pdiff) resource requests with 410 Gone.
    /// When disabled, diff requests are proxied to the upstream mirror but not cached
    /// (while full resources are always cached).
    #[serde(default = "default_reject_pdiff_requests")]
    pub(crate) reject_pdiff_requests: bool,

    #[serde(default = "default_experimental_parallel_hack_enabled")]
    pub(crate) experimental_parallel_hack_enabled: bool,

    #[serde(
        default = "default_experimental_parallel_hack_maxparallel",
        deserialize_with = "from_nonzero_usize"
    )]
    pub(crate) experimental_parallel_hack_maxparallel: Option<NonZero<usize>>,

    #[serde(
        default = "default_experimental_parallel_hack_statuscode",
        deserialize_with = "statuscode_from_u32"
    )]
    pub(crate) experimental_parallel_hack_statuscode: hyper::StatusCode,

    #[serde(default = "default_experimental_parallel_hack_retryafter")]
    pub(crate) experimental_parallel_hack_retryafter: u16,

    #[serde(default = "default_experimental_parallel_hack_factor")]
    pub(crate) experimental_parallel_hack_factor: f64,

    #[serde(
        default = "default_experimental_parallel_minsize",
        deserialize_with = "from_nonzero_u64_with_magnitude"
    )]
    pub(crate) experimental_parallel_hack_minsize: Option<NonZero<u64>>,
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

macro_rules! impl_parse_with_magnitude {
    ($name:ident, $T:ty) => {
        fn $name(s: &str) -> anyhow::Result<$T> {
            let s = s.trim();

            if let Ok(val) = s.parse::<$T>() {
                return Ok(val);
            }

            let Some(x) = s.find(|c| !char::is_ascii_digit(&c)) else {
                bail!("Could not split input");
            };

            let (val, mag) = s.split_at(x);

            let val = val.parse::<$T>()?;
            let mag = mag.trim();

            match mag {
                "k" => val
                    .checked_mul(1000)
                    .ok_or_else(|| anyhow!("Multiplication overflow")),
                "Ki" => val
                    .checked_mul(1024)
                    .ok_or_else(|| anyhow!("Multiplication overflow")),
                "M" => val
                    .checked_mul(1000 * 1000)
                    .ok_or_else(|| anyhow!("Multiplication overflow")),
                "Mi" => val
                    .checked_mul(1024 * 1024)
                    .ok_or_else(|| anyhow!("Multiplication overflow")),
                "G" => val
                    .checked_mul(1000 * 1000 * 1000)
                    .ok_or_else(|| anyhow!("Multiplication overflow")),
                "Gi" => val
                    .checked_mul(1024 * 1024 * 1024)
                    .ok_or_else(|| anyhow!("Multiplication overflow")),
                _ => bail!("Invalid magnitude `{mag}`, expected `k`, `Ki`, `M`, `Mi`, `G` or `Gi`"),
            }
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

fn statuscode_from_u32<'de, D>(deserializer: D) -> Result<hyper::StatusCode, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::Error as _;
    let v = Deserialize::deserialize(deserializer)?;

    hyper::StatusCode::from_u16(v).map_err(D::Error::custom)
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

const fn default_log_level() -> LevelFilter {
    DEFAULT_LOG_LEVEL
}

fn default_log_file() -> LogDestination {
    DEFAULT_LOG_DESTINATION
}

const fn default_bind_addr() -> IpAddr {
    DEFAULT_BIND_ADDRESS
}

const fn default_bind_port() -> NonZero<u16> {
    DEFAULT_BIND_PORT
}

fn default_database_path() -> PathBuf {
    PathBuf::from(DEFAULT_DATABASE_PATH)
}

fn default_cache_dir() -> PathBuf {
    PathBuf::from(DEFAULT_CACHE_DIR)
}

const fn default_db_slow_timeout() -> Duration {
    DEFAULT_DATABASE_SLOW_TIMEOUT
}

const fn default_http_timeout() -> Duration {
    DEFAULT_HTTP_TIMEOUT
}

const fn default_client_idle_timeout() -> Duration {
    DEFAULT_CLIENT_IDLE_TIMEOUT
}

const fn default_https_upgrade_mode() -> HttpsUpgradeMode {
    DEFAULT_HTTPS_UPGRADE_MODE
}

const fn default_buffer_size() -> usize {
    DEFAULT_BUF_SIZE
}

const fn default_aliases() -> Vec<Alias> {
    Vec::new()
}

const fn default_allowed_proxy_clients() -> Vec<IpNetOrAddr> {
    Vec::new()
}

const fn default_allowed_webif_clients() -> Option<Vec<IpNetOrAddr>> {
    None
}

const fn default_allowed_mirrors() -> Vec<ConfigDomainName> {
    Vec::new()
}

const fn default_http_only_mirrors() -> Vec<ConfigDomainName> {
    Vec::new()
}

const fn default_disk_quota() -> Option<NonZero<u64>> {
    DEFAULT_DISK_QUOTA
}

const fn default_https_tunnel_enabled() -> bool {
    DEFAULT_HTTPS_TUNNEL_ENABLED
}

fn default_https_tunnel_allowed_ports() -> Vec<NonZero<u16>> {
    DEFAULT_HTTPS_TUNNEL_ALLOWED_PORTS.to_vec()
}

const fn default_https_tunnel_allowed_mirrors() -> Vec<DomainName> {
    Vec::new()
}

const fn default_https_tunnel_max_connections_per_client() -> Option<NonZero<usize>> {
    DEFAULT_HTTPS_TUNNEL_MAX_CONNECTIONS_PER_CLIENT
}

const fn default_max_connections_per_client_ip() -> Option<NonZero<usize>> {
    DEFAULT_MAX_CONNECTIONS_PER_CLIENT_IP
}

const fn default_byhash_retention_days() -> NonZero<u64> {
    DEFAULT_BYHASH_RETENTION_DAYS
}

const fn default_usage_retention_days() -> Option<NonZero<u64>> {
    DEFAULT_USAGE_RETENTION_DAYS
}

const fn default_reject_pdiff_requests() -> bool {
    DEFAULT_REJECT_PDIFF_REQUESTS
}

const fn default_logstore_capacity() -> NonZero<usize> {
    DEFAULT_LOGSTORE_CAPACITY
}

const fn default_min_download_rate() -> Option<NonZero<usize>> {
    DEFAULT_MIN_DOWNLOAD_RATE
}

const fn default_rate_check_timeframe() -> NonZero<usize> {
    DEFAULT_RATE_CHECK_TIMEFRAME
}

const fn default_max_upstream_downloads() -> Option<NonZero<usize>> {
    DEFAULT_MAX_UPSTREAM_DOWNLOADS
}

const fn default_db_channel_capacity() -> NonZero<usize> {
    DEFAULT_DB_CHANNEL_CAPACITY
}

const fn default_db_batch_flush_max_count() -> NonZero<usize> {
    DEFAULT_DB_BATCH_FLUSH_MAX_COUNT
}

const fn default_db_batch_flush_interval_secs() -> NonZero<u64> {
    DEFAULT_DB_BATCH_FLUSH_INTERVAL_SECS
}

const fn default_mmap_threshold() -> NonZero<u64> {
    DEFAULT_MMAP_THRESHOLD
}

const fn default_max_object_size() -> Option<NonZero<u64>> {
    DEFAULT_MAX_OBJECT_SIZE
}

const fn default_upstream_tcp_nodelay() -> bool {
    DEFAULT_UPSTREAM_TCP_NODELAY
}

const fn default_experimental_parallel_hack_enabled() -> bool {
    DEFAULT_EXPERIMENTAL_PARALLEL_HACK_ENABLED
}

const fn default_experimental_parallel_hack_maxparallel() -> Option<NonZero<usize>> {
    DEFAULT_EXPERIMENTAL_PARALLEL_HACK_MAXPARALLEL
}

const fn default_experimental_parallel_hack_statuscode() -> hyper::StatusCode {
    DEFAULT_EXPERIMENTAL_PARALLEL_HACK_STATUSCODE
}

const fn default_experimental_parallel_hack_retryafter() -> u16 {
    DEFAULT_EXPERIMENTAL_PARALLEL_HACK_RETRYAFTER
}

const fn default_experimental_parallel_hack_factor() -> f64 {
    DEFAULT_EXPERIMENTAL_PARALLEL_HACK_FACTOR
}

const fn default_experimental_parallel_minsize() -> Option<NonZero<u64>> {
    DEFAULT_EXPERIMENTAL_PARALLEL_HACK_MINSIZE
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

#[must_use]
fn is_valid_config_domain(domain: &str) -> bool {
    /* No unicode characters allowed for now */

    let len = domain.len();
    if len == 0 || len > 253 {
        return false;
    }

    // IPv6 addresses contain colons; wildcards don't apply to them
    if domain.contains(':') {
        return domain.parse::<std::net::Ipv6Addr>().is_ok();
    }

    let mut is_wildcard = false;
    let mut part_count: u32 = 0;

    for (pos, part) in domain.split('.').enumerate() {
        if part.is_empty() || part.len() > 63 {
            return false;
        }

        part_count += 1;

        if pos == 0 && part == "*" {
            is_wildcard = true;
            continue;
        }

        for (pos, byte) in part.bytes().enumerate() {
            if byte == b'-' {
                if pos == 0 || pos == part.len() - 1 {
                    return false;
                }
            } else if !byte.is_ascii_alphanumeric() {
                return false;
            }
        }
    }

    if is_wildcard && part_count < 3 {
        return false;
    }

    // Reject wildcards that look like partial IPv4 addresses (e.g. "*.1.1")
    if is_wildcard {
        let suffix = domain.strip_prefix("*.").unwrap_or(domain);
        if suffix.split('.').all(|p| p.parse::<u8>().is_ok()) {
            return false;
        }
    }

    true
}

impl Config {
    /// Load the configuration from the given file.
    /// Return the loaded configuration, a flag indicating whether the default
    /// configuration file was not found and the built-in defaults were used
    /// instead, and a list of validation warnings.
    ///
    /// When supplied, `cache_directory` overrides [`Self::cache_directory`]
    /// and `database_path` overrides [`Self::database_path`], applied on top
    /// of the values from the configuration file (or the built-in defaults
    /// when no file is loaded). A non-default `file` that does not exist is
    /// always an error, even when both overrides are supplied.
    pub(crate) fn new(
        file: &Path,
        cache_directory: Option<PathBuf>,
        database_path: Option<PathBuf>,
    ) -> anyhow::Result<(Self, bool, Vec<String>)> {
        let (mut config, fallback) = match std::fs::read_to_string(file) {
            Ok(content) => (
                toml::from_str::<Self>(&content).context("Failed to parse configuration")?,
                false,
            ),
            Err(err)
                if err.kind() == std::io::ErrorKind::NotFound
                    && file == Path::new(DEFAULT_CONFIGURATION_PATH) =>
            {
                (
                    toml::from_str::<Self>("").expect("built-in defaults must parse"),
                    true,
                )
            }
            Err(err) => {
                return Err(err)
                    .with_context(|| format!("Failed to read file `{}`", file.display()));
            }
        };

        if let Some(path) = cache_directory {
            config.cache_directory = path;
        }
        if let Some(path) = database_path {
            config.database_path = path;
        }

        let warnings = config.validate()?;

        Ok((config, fallback, warnings))
    }

    fn validate(&mut self) -> anyhow::Result<Vec<String>> {
        let mut warnings: Vec<String> = Vec::new();
        // TODO: check bind_addr.is_documentation() once stable: https://github.com/rust-lang/rust/issues/27709

        if let LogDestination::File(ref path) = self.log_file {
            if path.as_os_str().is_empty() {
                bail!("Invalid log_file value: must not be empty");
            }

            if !path.is_absolute() {
                warnings.push(format!(
                    "log_file `{}` is not an absolute path",
                    path.display()
                ));
            }
        }

        if self.database_slow_timeout < Duration::from_secs(1)
            || self.database_slow_timeout > Duration::from_mins(1)
        {
            bail!(
                "Invalid database_slow_timeout value of {}s: must be between 1s and 60s",
                self.database_slow_timeout.as_secs_f32()
            );
        }

        if self.http_timeout < Duration::from_secs(1) || self.http_timeout > Duration::from_mins(6)
        {
            bail!(
                "Invalid http_timeout value of {}s: must be between 1s and 360s",
                self.http_timeout.as_secs_f32()
            );
        }

        if self.client_idle_timeout < Duration::from_secs(1)
            || self.client_idle_timeout > Duration::from_hours(1)
        {
            bail!(
                "Invalid client_idle_timeout value of {}s: must be between 1s and 3600s",
                self.client_idle_timeout.as_secs_f32()
            );
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

        if self.buffer_size < 1024 || self.buffer_size > 1024 * 1024 * 1024 {
            bail!(
                "Invalid buffer_size value of {}: must be in between 1k and 1G",
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
                quota.get()
            ));
        }

        if let Some(max_object_size) = self.max_object_size {
            if max_object_size < VOLATILE_UNKNOWN_CONTENT_LENGTH_UPPER {
                bail!(
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
                    max_object_size.get()
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
            bail!(
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
            bail!(
                "Invalid usage_retention_days value of {}: Overflow",
                days.get()
            );
        }

        if self.db_channel_capacity > nonzero!(4096) {
            bail!(
                "Invalid db_channel_capacity value of {}: must be between 1 and 4096",
                self.db_channel_capacity
            );
        }

        if self.db_batch_flush_max_count > nonzero!(4096) {
            bail!(
                "Invalid db_batch_flush_max_count value of {}: must be between 1 and 4096",
                self.db_batch_flush_max_count
            );
        }

        if self.db_batch_flush_interval_secs > nonzero!(300) {
            bail!(
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
                    bail!("Alias {} conflicts with alias {}", alias.main, falias.main);
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

        if !self.https_tunnel_enabled
            && self.https_tunnel_allowed_ports != default_https_tunnel_allowed_ports()
        {
            warnings.push(
                "https_tunnel_allowed_ports is set but https_tunnel_enabled is false".to_string(),
            );
        }

        if !self.https_tunnel_enabled
            && self.https_tunnel_allowed_mirrors != default_https_tunnel_allowed_mirrors()
        {
            warnings.push(
                "https_tunnel_allowed_mirrors is set but https_tunnel_enabled is false".to_string(),
            );
        }

        if !self.https_tunnel_enabled && self.https_tunnel_max_connections_per_client.is_some() {
            warnings.push(
                "https_tunnel_max_connections_per_client is set but https_tunnel_enabled is false"
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

        if self.min_download_rate.is_none()
            && self.rate_check_timeframe != default_rate_check_timeframe()
        {
            bail!(
                "rate_check_timeframe is set to {}s but min_download_rate is not configured",
                self.rate_check_timeframe
            );
        }

        if self.rate_check_timeframe > nonzero!(360) {
            bail!(
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
        if self.mmap_threshold != DEFAULT_MMAP_THRESHOLD {
            warnings.push(format!(
                "mmap_threshold is set to {} but mmap feature is not enabled",
                self.mmap_threshold
            ));
        }

        #[expect(clippy::float_cmp, reason = "compare against default value")]
        if !self.experimental_parallel_hack_enabled
            && (self.experimental_parallel_hack_maxparallel
                != default_experimental_parallel_hack_maxparallel()
                || self.experimental_parallel_hack_statuscode
                    != default_experimental_parallel_hack_statuscode()
                || self.experimental_parallel_hack_retryafter
                    != default_experimental_parallel_hack_retryafter()
                || self.experimental_parallel_hack_factor
                    != default_experimental_parallel_hack_factor()
                || self.experimental_parallel_hack_minsize
                    != default_experimental_parallel_minsize())
        {
            warnings.push(
                "experimental_parallel_hack options are set but experimental_parallel_hack_enabled is false".to_string(),
            );
        }

        if !self.experimental_parallel_hack_factor.is_normal()
            || self.experimental_parallel_hack_factor <= 0.0
            || self.experimental_parallel_hack_factor > 1.0
        {
            bail!(
                "Invalid experimental_parallel_hack_factor of {}: must be between 0 and 1",
                self.experimental_parallel_hack_factor
            );
        }

        if self.experimental_parallel_hack_retryafter < 1
            || self.experimental_parallel_hack_retryafter > 300
        {
            bail!(
                "Invalid experimental_parallel_hack_retryafter value of {}: must be between 1 and 300",
                self.experimental_parallel_hack_retryafter
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

        if self.cache_directory.as_os_str().is_empty() {
            bail!("Invalid cache_directory value: must not be empty");
        }

        if !self.cache_directory.is_absolute() {
            warnings.push(format!(
                "cache_directory `{}` is not an absolute path",
                self.cache_directory.display()
            ));
        }

        if self.database_path.as_os_str().is_empty() {
            bail!("Invalid database_path value: must not be empty");
        }

        if !self.database_path.is_absolute() {
            warnings.push(format!(
                "database_path `{}` is not an absolute path",
                self.database_path.display()
            ));
        }

        Ok(warnings)
    }
}

#[cfg(test)]
mod test {
    use super::*;

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

        // too long port
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
}
