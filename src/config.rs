use std::cmp::Ordering;
use std::net::IpAddr;
use std::net::Ipv6Addr;
use std::num::NonZero;
use std::ops::Deref;
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

#[macro_export]
macro_rules! nonzero {
    ($exp:expr) => {
        const {
            match NonZero::new($exp) {
                Some(v) => v,
                None => panic!("Value is zero"),
            }
        }
    };
}

pub(crate) const DEFAULT_BIND_ADDRESS: IpAddr = IpAddr::V6(Ipv6Addr::UNSPECIFIED);
pub(crate) const DEFAULT_BIND_PORT: NonZero<u16> = nonzero!(3142);
pub(crate) const DEFAULT_BUF_SIZE: usize = 32 * 1024; // 32 MiB
pub(crate) const DEFAULT_CACHE_DIR: &str = "/var/cache/apt-cacher-rs";
pub(crate) const DEFAULT_CONFIGURATION_PATH: &str = "/etc/apt-cacher-rs/apt-cacher-rs.conf";
pub(crate) const DEFAULT_DATABASE_PATH: &str = "/var/lib/apt-cacher-rs/apt-cacher-rs.db";
pub(crate) const DEFAULT_DATABASE_SLOW_TIMEOUT: Duration = Duration::from_secs(2);
pub(crate) const DEFAULT_DISK_QUOTA: Option<NonZero<u64>> = None;
pub(crate) const DEFAULT_HTTP_TIMEOUT: Duration = Duration::from_secs(10);
pub(crate) const DEFAULT_HTTPS_TUNNEL_ENABLED: bool = true;
pub(crate) const DEFAULT_HTTPS_TUNNEL_ALLOWED_PORTS: [NonZero<u16>; 1] = [nonzero!(443)];
pub(crate) const DEFAULT_LOG_LEVEL: LevelFilter = LevelFilter::Info;
pub(crate) const DEFAULT_LOGSTORE_CAPACITY: NonZero<usize> = nonzero!(100);
pub(crate) const DEFAULT_MIN_DOWNLOAD_RATE: Option<NonZero<usize>> = Some(nonzero!(10000)); // 10 kB/s
pub(crate) const DEFAULT_BYHASH_RETENTION_DAYS: u64 = 90;
pub(crate) const DEFAULT_USAGE_RETENTION_DAYS: u64 = 30;
pub(crate) const DEFAULT_EXPERIMENTAL_PARALLEL_HACK_ENABLED: bool = false;
pub(crate) const DEFAULT_EXPERIMENTAL_PARALLEL_HACK_MAXPARALLEL: Option<NonZero<usize>> =
    Some(nonzero!(3));
pub(crate) const DEFAULT_EXPERIMENTAL_PARALLEL_HACK_STATUSCODE: hyper::StatusCode =
    hyper::StatusCode::TOO_MANY_REQUESTS;
pub(crate) const DEFAULT_EXPERIMENTAL_PARALLEL_HACK_RETRYAFTER: u16 = 5;
pub(crate) const DEFAULT_EXPERIMENTAL_PARALLEL_HACK_FACTOR: f64 = 0.2;
pub(crate) const DEFAULT_EXPERIMENTAL_PARALLEL_HACK_MINSIZE: Option<NonZero<u64>> =
    Some(nonzero!(10 * 1024 * 1024)); // 10 MiB

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum ConfigDomainName {
    Wildcard(String),
    Full(String),
}

impl ConfigDomainName {
    pub(crate) fn new(domain: String) -> Result<Self, String> {
        if is_valid_config_domain(&domain) {
            match domain.strip_prefix('*') {
                Some(d) => Ok(Self::Wildcard(d.to_string())),
                None => Ok(Self::Full(domain)),
            }
        } else {
            Err(domain)
        }
    }

    #[must_use]
    pub(crate) fn permits(&self, domain: &str) -> bool {
        match self {
            Self::Wildcard(d) => domain.ends_with(d),
            Self::Full(d) => domain == d,
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

#[derive(Clone, Debug, Hash, PartialEq, Eq, PartialOrd, Ord, sqlx::Type)]
#[sqlx(transparent)]
pub(crate) struct DomainName(String);

impl DomainName {
    pub(crate) fn new(domain: String) -> Result<Self, String> {
        if is_valid_domain(&domain) {
            Ok(Self(domain))
        } else {
            Err(domain)
        }
    }
}

impl Deref for DomainName {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::fmt::Display for DomainName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
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
        self.0.as_ref()
    }
}

impl From<std::string::String> for DomainName {
    fn from(value: std::string::String) -> Self {
        Self::new(value).expect("Caller must ensure value is a valid domain")
    }
}

impl From<DomainName> for std::string::String {
    fn from(val: DomainName) -> Self {
        val.0
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Alias {
    pub(crate) main: DomainName,
    pub(crate) aliases: Vec<DomainName>,
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

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Config {
    /// Minimum log level severity to output.
    /// Can be overridden via program options.
    #[serde(default = "default_log_level", deserialize_with = "from_level_name")]
    pub(crate) log_level: LevelFilter,

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

    /// Timeout of database operations after which a warning is generated.
    #[serde(
        default = "default_db_slow_timeout",
        deserialize_with = "from_secs_f32"
    )]
    pub(crate) database_slow_timeout: Duration,

    /// Timeout for http operations.
    #[serde(default = "default_http_timeout", deserialize_with = "from_secs_f32")]
    pub(crate) http_timeout: Duration,

    /// Size of buffer used for internal data transfer.
    #[serde(
        default = "default_buffer_size",
        deserialize_with = "from_usize_with_magnitude"
    )]
    pub(crate) buffer_size: usize,

    /// Number of stored error and warning log messages.
    #[serde(default = "default_logstore_capacity")]
    pub(crate) logstore_capacity: NonZero<usize>,

    /// Disk quota for cache.
    #[serde(
        default = "default_disk_quota",
        deserialize_with = "from_nonzero_u64_with_magnitude"
    )]
    pub(crate) disk_quota: Option<NonZero<u64>>,

    /// Retention time for files acquired "by-hash".
    #[serde(default = "default_byhash_retention_days")]
    pub(crate) byhash_retention_days: u64,

    /// Retention time for usage logs.
    #[serde(default = "default_usage_retention_days")]
    pub(crate) usage_retention_days: u64,

    /// Mirror aliases.
    #[serde(default = "default_aliases")]
    pub(crate) aliases: Vec<Alias>,

    /// List of allowed mirrors.
    #[serde(default = "default_allowed_mirrors")]
    pub(crate) allowed_mirrors: Vec<ConfigDomainName>,

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
    pub(crate) https_tunnel_allowed_mirrors: Vec<String>,

    /// Minimum transfer rate for downloads and uploads.
    /// Connections that fail to fulfill this limit are cancelled.
    #[serde(
        default = "default_min_download_rate",
        deserialize_with = "from_nonzero_usize_with_magnitude"
    )]
    pub(crate) min_download_rate: Option<NonZero<usize>>,

    #[serde(default = "default_experimental_parallel_hack_enabled")]
    pub(crate) experimental_parallel_hack_enabled: bool,

    #[serde(default = "default_experimental_parallel_hack_maxparallel")]
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

fn from_secs_f32<'de, D>(deserializer: D) -> Result<Duration, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::Error as _;
    let s: f32 = Deserialize::deserialize(deserializer)?;

    Duration::try_from_secs_f32(s).map_err(D::Error::custom)
}

fn from_usize_with_magnitude<'de, D>(deserializer: D) -> Result<usize, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::Error as _;
    let s: String = Deserialize::deserialize(deserializer)?;

    parse_usize_with_magnitude(&s).map_err(D::Error::custom)
}

fn parse_usize_with_magnitude(s: &str) -> anyhow::Result<usize> {
    debug_assert_eq!(s, s.trim(), "Should be trimmed by deserializer");

    if let Ok(val) = s.parse::<usize>() {
        return Ok(val);
    }

    let Some(x) = s.find(|c| !char::is_ascii_digit(&c)) else {
        bail!("Could not split input");
    };

    let (val, mag) = s.split_at(x);

    let val = val.parse::<usize>()?;
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

fn parse_u64_with_magnitude(s: &str) -> anyhow::Result<u64> {
    debug_assert_eq!(s, s.trim(), "Should be trimmed by deserializer");

    if let Ok(val) = s.parse::<u64>() {
        return Ok(val);
    }

    let Some(x) = s.find(|c| !char::is_ascii_digit(&c)) else {
        bail!("Could not split input");
    };

    let (val, mag) = s.split_at(x);

    let val = val.parse::<u64>()?;
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

fn statuscode_from_u32<'de, D>(deserializer: D) -> Result<hyper::StatusCode, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::Error as _;
    let v = Deserialize::deserialize(deserializer)?;

    hyper::StatusCode::from_u16(v).map_err(D::Error::custom)
}

const fn default_log_level() -> LevelFilter {
    DEFAULT_LOG_LEVEL
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

const fn default_disk_quota() -> Option<NonZero<u64>> {
    DEFAULT_DISK_QUOTA
}

const fn default_https_tunnel_enabled() -> bool {
    DEFAULT_HTTPS_TUNNEL_ENABLED
}

fn default_https_tunnel_allowed_ports() -> Vec<NonZero<u16>> {
    DEFAULT_HTTPS_TUNNEL_ALLOWED_PORTS.to_vec()
}

const fn default_https_tunnel_allowed_mirrors() -> Vec<String> {
    Vec::new()
}

const fn default_byhash_retention_days() -> u64 {
    DEFAULT_BYHASH_RETENTION_DAYS
}

const fn default_usage_retention_days() -> u64 {
    DEFAULT_USAGE_RETENTION_DAYS
}

const fn default_logstore_capacity() -> NonZero<usize> {
    DEFAULT_LOGSTORE_CAPACITY
}

const fn default_min_download_rate() -> Option<NonZero<usize>> {
    DEFAULT_MIN_DOWNLOAD_RATE
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
    debug_assert!(a.is_sorted());
    debug_assert!(b.is_sorted());

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

#[must_use]
pub(crate) fn is_valid_domain(domain: &str) -> bool {
    /* No unicode characters allowed for now */

    for part in domain.split('.') {
        if part.is_empty() || part.len() > 64 {
            return false;
        }

        for (pos, char) in part.chars().enumerate() {
            if char == '-' {
                if pos == 0 || pos == part.len() - 1 {
                    return false;
                }
            } else if !char.is_ascii_alphanumeric() {
                return false;
            }
        }
    }

    true
}

#[must_use]
pub(crate) fn is_valid_config_domain(domain: &str) -> bool {
    /* No unicode characters allowed for now */

    for (pos, part) in domain.split('.').enumerate() {
        if part.is_empty() || part.len() > 64 {
            return false;
        }

        if pos == 0 && part == "*" {
            continue;
        }

        for (pos, char) in part.chars().enumerate() {
            if char == '-' {
                if pos == 0 || pos == part.len() - 1 {
                    return false;
                }
            } else if !char.is_ascii_alphanumeric() {
                return false;
            }
        }
    }

    true
}

impl Config {
    fn default() -> Self {
        Self {
            log_level: DEFAULT_LOG_LEVEL,
            bind_addr: DEFAULT_BIND_ADDRESS,
            bind_port: DEFAULT_BIND_PORT,
            database_path: PathBuf::from(DEFAULT_DATABASE_PATH),
            cache_directory: PathBuf::from(DEFAULT_CACHE_DIR),
            database_slow_timeout: DEFAULT_DATABASE_SLOW_TIMEOUT,
            http_timeout: DEFAULT_HTTP_TIMEOUT,
            buffer_size: DEFAULT_BUF_SIZE,
            aliases: Vec::new(),
            allowed_mirrors: Vec::new(),
            disk_quota: None,
            allowed_proxy_clients: Vec::new(),
            allowed_webif_clients: None,
            https_tunnel_enabled: true,
            https_tunnel_allowed_ports: DEFAULT_HTTPS_TUNNEL_ALLOWED_PORTS.to_vec(),
            https_tunnel_allowed_mirrors: Vec::new(),
            byhash_retention_days: DEFAULT_BYHASH_RETENTION_DAYS,
            usage_retention_days: DEFAULT_USAGE_RETENTION_DAYS,
            logstore_capacity: DEFAULT_LOGSTORE_CAPACITY,
            min_download_rate: DEFAULT_MIN_DOWNLOAD_RATE,
            experimental_parallel_hack_enabled: DEFAULT_EXPERIMENTAL_PARALLEL_HACK_ENABLED,
            experimental_parallel_hack_maxparallel: DEFAULT_EXPERIMENTAL_PARALLEL_HACK_MAXPARALLEL,
            experimental_parallel_hack_statuscode: DEFAULT_EXPERIMENTAL_PARALLEL_HACK_STATUSCODE,
            experimental_parallel_hack_retryafter: DEFAULT_EXPERIMENTAL_PARALLEL_HACK_RETRYAFTER,
            experimental_parallel_hack_factor: DEFAULT_EXPERIMENTAL_PARALLEL_HACK_FACTOR,
            experimental_parallel_hack_minsize: DEFAULT_EXPERIMENTAL_PARALLEL_HACK_MINSIZE,
        }
    }

    pub(crate) fn new(file: &Path) -> anyhow::Result<(Self, bool)> {
        let content = match std::fs::read_to_string(file) {
            Ok(c) => c,
            Err(err)
                if err.kind() == std::io::ErrorKind::NotFound
                    && file == Path::new(DEFAULT_CONFIGURATION_PATH) =>
            {
                return Ok((Self::default(), true));
            }
            Err(err) => {
                return Err(err)
                    .with_context(|| format!("Failed to read file `{}`", file.display()));
            }
        };

        let mut config: Self = toml::from_str(&content).context("Failed to parse configuration")?;

        config.validate()?;

        Ok((config, false))
    }

    fn validate(&mut self) -> anyhow::Result<()> {
        // TODO: check bind_addr.is_documentation() once stable: https://github.com/rust-lang/rust/issues/27709

        if self.database_slow_timeout > Duration::from_mins(1) {
            bail!(
                "Invalid database_slow_timeout value of {}: must be less or equal to 60s",
                self.database_slow_timeout.as_secs_f32()
            );
        }

        if self.http_timeout > Duration::from_mins(6) {
            bail!(
                "Invalid http_timeout value of {}: must be less or equal to 360s",
                self.http_timeout.as_secs_f32()
            );
        }

        if self.buffer_size < 1024 || self.buffer_size > 1024 * 1024 * 1024 {
            bail!(
                "Invalid buffer_size value of {}: must be in between 1K and 1G",
                self.buffer_size
            );
        }

        if self
            .usage_retention_days
            .checked_mul(24 * 60 * 60)
            .is_none()
        {
            bail!(
                "Invalid usage retention days value of {}: Overflow",
                self.usage_retention_days
            );
        }

        if self.experimental_parallel_hack_factor <= 0.0
            || self.experimental_parallel_hack_factor > 1.0
        {
            bail!(
                "Invalid experimental parallel hack factor of {}: must be between 0 and 1",
                self.experimental_parallel_hack_factor
            );
        }

        /* Alias validation */
        {
            for alias in &mut self.aliases {
                alias.aliases.sort();
            }

            for (pos, alias) in self.aliases.iter().enumerate() {
                let remaining_aliases = &self.aliases.as_slice()[pos + 1..];

                if let Some(falias) = remaining_aliases.iter().find(|ialias| {
                    ialias.main == alias.main
                        || ialias.aliases.binary_search(&alias.main).is_ok()
                        || alias.aliases.binary_search(&ialias.main).is_ok()
                        || intersect(&ialias.aliases, &alias.aliases)
                }) {
                    bail!("Alias {} conflicts with alias {}", alias.main, falias.main);
                }
            }
        }

        self.allowed_mirrors.sort();
        self.https_tunnel_allowed_ports.sort();
        self.https_tunnel_allowed_mirrors.sort();

        Ok(())
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
    fn test_is_valid_domain() {
        assert!(is_valid_domain("debian.org"));

        assert!(is_valid_domain("salsa.debian.org"));

        assert!(is_valid_domain("metadata.ftp-master.debian.org"));

        // double dots
        assert!(!is_valid_domain("debian..org"));

        // short part
        assert!(is_valid_domain("debian.f.org"));

        // too long port
        assert!(!is_valid_domain(
            "debian.abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789AAA.org"
        ));

        // starting dash
        assert!(!is_valid_domain("-debian.org"));

        // ending dash
        assert!(!is_valid_domain("debian-.org"));

        // dash in position 2
        assert!(is_valid_domain("d-ebian.org"));

        // dash in position 3
        assert!(is_valid_domain("de-bian.org"));

        // dash in position 4
        assert!(is_valid_domain("deb-ian.org"));

        // dash in position 5
        assert!(is_valid_domain("debi-an.org"));

        // invalid char
        assert!(!is_valid_domain("deb_ian.org"));

        // special directory entry
        assert!(!is_valid_domain("."));
        assert!(!is_valid_domain(".."));
        assert!(!is_valid_domain("foo/bar"));

        // wild card
        assert!(!is_valid_domain("*.debian.org"));
        assert!(!is_valid_domain("*e.debian.org"));
        assert!(!is_valid_domain("deb.*.debian.org"));
        assert!(!is_valid_domain("debian.*"));
    }

    #[test]
    fn test_is_valid_config_domain() {
        assert!(is_valid_config_domain("debian.org"));

        assert!(is_valid_config_domain("salsa.debian.org"));

        assert!(is_valid_config_domain("metadata.ftp-master.debian.org"));

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
    }
}
