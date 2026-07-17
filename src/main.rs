#![allow(
    clippy::too_many_lines,
    reason = "prefer documented and clear structure"
)]

#[cfg(not(any(feature = "tls_hyper", feature = "tls_rustls")))]
compile_error!("Either feature \"tls_hyper\" or \"tls_rustls\" must be enabled for this crate.");

#[cfg(all(feature = "tls_hyper", feature = "tls_rustls"))]
compile_error!("Feature \"tls_hyper\" and \"tls_rustls\" are mutually exclusive.");

#[cfg(target_env = "musl")]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

mod active_downloads;
mod cache_conditional;
mod cache_layout;
mod cache_metadata;
mod cache_quota;
mod channel_body;
mod cleanup;
mod client_counter;
mod config;
mod database;
mod database_task;
mod deb_mirror;
mod error;
mod flat_blocklist;
mod guards;
mod http_etag;
#[cfg(feature = "sendfile")]
mod http_helpers;
mod http_last_modified;
mod http_range;
mod humanfmt;
mod hyper_conn;
mod index_parser;
mod integrity;
#[cfg(feature = "ktls")]
mod ktls;
#[cfg(feature = "ktls")]
mod ktls_handshake;
mod limits;
mod log_once;
mod logstore;
mod main_loop;
mod metrics;
#[cfg(feature = "mmap")]
mod mmap_body;
mod permitted_host_cache;
mod precise_instant;
mod rate_checked_body;
mod rate_checker;
mod rate_log;
mod request_dispatch;
mod ringbuffer;
#[cfg(feature = "ktls")]
mod secure_vec;
#[cfg(feature = "sendfile")]
mod sendfile_conn;
mod small_vec_deque;
#[cfg(feature = "splice")]
mod splice_conn;
mod task_cache_scan;
mod task_setup;
#[cfg(feature = "splice")]
mod tcp_cork_guard;
mod uncacheables;
mod utils;
mod verify_throttle;
mod web_interface;
mod xattr_helpers;
mod xz_stream;

use std::{
    fmt::Debug,
    fmt::Display,
    hash::Hash,
    io::IsTerminal as _,
    net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4},
    num::NonZero,
    path::{Path, PathBuf},
    pin::Pin,
    sync::{
        Arc, OnceLock,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use clap::Parser;
use hashbrown::{Equivalent, HashMap};
use http::{
    Response, StatusCode,
    header::{ALLOW, CONNECTION, CONTENT_TYPE, DATE, SERVER, VIA},
};
use http_body::{Body, Frame, SizeHint};
use http_body_util::{BodyExt as _, Full, combinators::BoxBody};
use hyper_util::client::legacy::connect::HttpConnector;
use pin_project::pin_project;
#[cfg(feature = "mmap")]
use rate_checked_body::{MaybeRated, RateCheckedBodyErr};
use time::format_description::well_known::Rfc2822;
use tokio::runtime::Builder;
use tracing::{debug, error, info, trace, warn};
use tracing_subscriber::{Layer as _, layer::SubscriberExt as _, util::SubscriberInitExt as _};

// TODO: replace usages with ! once stable
enum Never {}

#[expect(
    clippy::cast_possible_truncation,
    reason = "on truncation the final comparison fails"
)]
const _: () = assert!(
    ((usize::MAX as u64) as usize) == usize::MAX,
    "ensure casts from usize to u64 via 'as' do not truncate"
);

pub(crate) const APP_NAME: &str = env!("CARGO_PKG_NAME");
const APP_VERSION: &str = env!("CARGO_PKG_VERSION");
const APP_USER_AGENT: &str = concat!(env!("CARGO_PKG_NAME"), "/", env!("CARGO_PKG_VERSION"),);

pub(crate) const APP_VIA: &str = concat!("1.1 ", env!("CARGO_PKG_NAME"));

const RETENTION_TIME: Duration = Duration::from_hours(8 * 7 * 24); /* 8 weeks */

pub(crate) const VOLATILE_UNKNOWN_CONTENT_LENGTH_UPPER: NonZero<u64> = nonzero!(1024 * 1024); /* 1MiB */

/// Maximum age for volatile cache entries before they are treated as stale.
pub(crate) const VOLATILE_CACHE_MAX_AGE: Duration = Duration::from_secs(30);

/// Maximum time to wait for the database task to drain on shutdown before giving up.
const DB_DRAIN_TIMEOUT: Duration = Duration::from_secs(15);

/// Warn (once) if the upstream `Content-Type` differs from the type derived
/// from the cached file's basename. The non-standard `binary/octet-stream`
/// is widely advertised by Debian mirrors and is treated as a no-op rather
/// than a mismatch to keep the log quiet.
pub(crate) fn warn_on_content_type_mismatch(
    upstream: Option<&str>,
    mirror: &deb_mirror::Mirror,
    debname: &str,
) {
    let Some(upstream_ct) = upstream else {
        return;
    };
    if upstream_ct.eq_ignore_ascii_case("binary/octet-stream") {
        return;
    }

    let expected = content_type_for_cached_file(debname);
    if upstream_ct.eq_ignore_ascii_case(expected) {
        return;
    }
    // `application/x-deb` is the legacy unregistered alias for the
    // IANA-registered `application/vnd.debian.binary-package`; treat them
    // as equivalent.
    if expected == "application/vnd.debian.binary-package"
        && upstream_ct.eq_ignore_ascii_case("application/x-deb")
    {
        return;
    }
    // `application/x-gzip` is the legacy non-standard alias for the
    // IANA-registered `application/gzip` (RFC 6713); treat them as equivalent.
    if expected == "application/gzip" && upstream_ct.eq_ignore_ascii_case("application/x-gzip") {
        return;
    }
    warn_once_or_info!(
        "Upstream Content-Type `{upstream_ct}` differs from expected `{expected}` for {debname} from {mirror}"
    );
}

/// Derive the Content-Type for a cached file based on its filename extension.
#[must_use]
pub(crate) fn content_type_for_cached_file(filename: &str) -> &'static str {
    if deb_mirror::is_deb_package(filename) {
        return "application/vnd.debian.binary-package";
    }

    // Match on the basename so both flat (`Packages`) and structured
    // (`sid_main_binary-amd64_Packages`) debnames classify correctly.
    let basename = filename.rsplit_once('_').map_or(filename, |(_, b)| b);
    if matches!(basename, "InRelease" | "Release" | "Packages" | "Sources") {
        return "text/plain";
    }

    let extension = filename.rsplit_once('.').map(|(_, ext)| ext);

    match extension {
        Some("gz") => "application/gzip",
        Some("xz") => "application/x-xz",
        Some("bz2") => "application/x-bzip2",
        Some("lz4") => "application/x-lz4",
        Some("zst") => "application/zstd",
        Some("gpg") => "application/pgp-signature",
        _ => "application/octet-stream",
    }
}

#[derive(Copy, Clone, Debug)]
pub(crate) struct ClientInfo {
    addr: SocketAddr,
    is_cleanup: bool,
}

/// Address attached to in-process requests synthesised by `task_cleanup`
/// (Packages fetches for the GC reference set).  Distinct from `127.0.0.1`
/// so logging and metrics can distinguish real loopback clients from the
/// cleanup-driven probes.
pub(crate) const CLEANUP_CLIENT_ADDR: SocketAddr =
    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 2), 0));

impl ClientInfo {
    #[must_use]
    pub(crate) fn new(addr: SocketAddr) -> Self {
        Self {
            addr,
            is_cleanup: false,
        }
    }

    #[must_use]
    pub(crate) fn new_cleanup() -> Self {
        Self {
            addr: CLEANUP_CLIENT_ADDR,
            is_cleanup: true,
        }
    }

    #[must_use]
    #[inline]
    pub(crate) fn ip(&self) -> IpAddr {
        self.addr.ip().to_canonical()
    }

    /// `true` when this client is the in-process sentinel used by
    /// `task_cleanup` to fetch a Packages index — never a real client.
    /// Used by upstream-error logging to demote a routine 4xx during a
    /// cleanup probe (e.g. the deliberate `.xz → .gz → raw` walk) from
    /// WARN to DEBUG.
    #[must_use]
    #[inline]
    pub(crate) fn is_cleanup_synthetic(&self) -> bool {
        self.is_cleanup
    }
}

impl Display for ClientInfo {
    #[inline]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.ip())
    }
}

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

#[derive(Debug, Eq, Hash, PartialEq)]
pub(crate) struct SchemeKey {
    host: String,
    port: Option<u16>,
}

#[derive(Hash)]
pub(crate) struct SchemeKeyRef<'a> {
    pub(crate) host: &'a str,
    pub(crate) port: Option<u16>,
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

pub(crate) static SCHEME_CACHE: OnceLock<parking_lot::RwLock<HashMap<SchemeKey, Scheme>>> =
    OnceLock::new();

#[cfg(feature = "ktls")]
pub(crate) static KTLS_BLOCKED: OnceLock<
    parking_lot::RwLock<HashMap<SchemeKey, coarsetime::Instant>>,
> = OnceLock::new();

#[must_use]
fn quick_response<T: Into<bytes::Bytes>>(
    status: StatusCode,
    message: T,
) -> Response<ProxyCacheBody> {
    let mut builder = Response::builder()
        .status(status)
        .header(SERVER, APP_NAME)
        .header(VIA, APP_VIA)
        .header(DATE, &*http_range::format_http_date())
        .header(CONNECTION, "keep-alive")
        .header(CONTENT_TYPE, "text/plain; charset=utf-8");

    if status == StatusCode::METHOD_NOT_ALLOWED {
        builder = builder.header(ALLOW, "GET");
    }

    builder.body(full_body(message)).expect("Response is valid")
}

/// Box `Full<Bytes>` into [`ProxyCacheBody::Boxed`] for
/// small, fully-buffered responses (status pages, HTML, static assets).
pub(crate) fn full_body<T: Into<bytes::Bytes>>(content: T) -> ProxyCacheBody {
    let body = Full::new(content.into()).map_err(|never| match never {});
    ProxyCacheBody::Boxed(BoxBody::new(body))
}

#[pin_project(project = EnumProj)]
#[cfg_attr(
    feature = "mmap",
    expect(
        clippy::large_enum_variant,
        reason = "Mmap is the zero-allocation hot path; boxing it would add a heap \
                  alloc per cached-file response which is exactly what this variant exists to avoid"
    )
)]
enum ProxyCacheBody {
    #[cfg(feature = "mmap")]
    Mmap(#[pin] MaybeRated<mmap_body::MmapBody>, ClientInfo),
    Boxed(#[pin] BoxBody<bytes::Bytes, Box<error::ProxyCacheError>>),
}

impl Debug for ProxyCacheBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            #[cfg(feature = "mmap")]
            Self::Mmap(_, _) => f.debug_tuple("Mmap").finish(),
            Self::Boxed(_) => f.debug_tuple("Boxed").finish(),
        }
    }
}

impl Body for ProxyCacheBody {
    type Data = ProxyCacheBodyData;

    type Error = Box<error::ProxyCacheError>;

    #[inline]
    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        match self.project() {
            #[cfg(feature = "mmap")]
            EnumProj::Mmap(memory_map, client) => memory_map
                .poll_frame(cx)
                .map_ok(|frame| frame.map_data(ProxyCacheBodyData::Mmap))
                .map_err(|rerr| match *rerr {
                    RateCheckedBodyErr::RateTimeout(error) => {
                        Box::new(error::ProxyCacheError::ClientDownloadRate {
                            error,
                            client: *client,
                        })
                    }
                    RateCheckedBodyErr::Inner(never) => match never {},
                }),

            EnumProj::Boxed(bytes) => bytes
                .poll_frame(cx)
                .map_ok(|frame| frame.map_data(ProxyCacheBodyData::Bytes)),
        }
    }

    #[inline]
    fn size_hint(&self) -> SizeHint {
        match self {
            #[cfg(feature = "mmap")]
            Self::Mmap(mmap_body, _) => mmap_body.size_hint(),
            Self::Boxed(box_body) => box_body.size_hint(),
        }
    }

    #[inline]
    fn is_end_stream(&self) -> bool {
        match self {
            #[cfg(feature = "mmap")]
            Self::Mmap(mmap_body, _) => mmap_body.is_end_stream(),
            Self::Boxed(box_body) => box_body.is_end_stream(),
        }
    }
}

enum ProxyCacheBodyData {
    #[cfg(feature = "mmap")]
    Mmap(mmap_body::MmapData),
    Bytes(bytes::Bytes),
}

impl bytes::buf::Buf for ProxyCacheBodyData {
    fn remaining(&self) -> usize {
        match self {
            #[cfg(feature = "mmap")]
            Self::Mmap(memory_map) => memory_map.remaining(),
            Self::Bytes(bytes) => bytes.remaining(),
        }
    }

    fn chunk(&self) -> &[u8] {
        match self {
            #[cfg(feature = "mmap")]
            Self::Mmap(memory_map) => memory_map.chunk(),
            Self::Bytes(bytes) => bytes.chunk(),
        }
    }

    fn advance(&mut self, cnt: usize) {
        match self {
            #[cfg(feature = "mmap")]
            Self::Mmap(memory_map) => memory_map.advance(cnt),
            Self::Bytes(bytes) => bytes.advance(cnt),
        }
    }
}

#[derive(Clone)]
pub(crate) struct AppState {
    pub(crate) database: database::Database,
    pub(crate) https_client: hyper_conn::HttpClient,
    pub(crate) active_downloads: active_downloads::ActiveDownloads,
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum ContentLength {
    /// An exact size
    Exact(NonZero<u64>),
    /// A limit for an unknown size
    Unknown(NonZero<u64>),
}

impl ContentLength {
    #[must_use]
    const fn upper(self) -> NonZero<u64> {
        match self {
            Self::Exact(s) | Self::Unknown(s) => s,
        }
    }
}

impl std::fmt::Display for ContentLength {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Exact(size) => write!(f, "exact {size} bytes"),
            Self::Unknown(limit) => write!(f, "up to {limit} bytes"),
        }
    }
}

#[must_use]
#[inline]
pub(crate) const fn get_features(version: bool) -> &'static str {
    #[cfg(all(feature = "tls_hyper", not(feature = "tls_rustls")))]
    macro_rules! feature_tls {
        () => {
            "hyper"
        };
    }

    #[cfg(feature = "tls_rustls")]
    macro_rules! feature_tls {
        () => {
            "rustls"
        };
    }

    // Expand to the literal "true" when `feature` is enabled, "false" otherwise.
    macro_rules! feature_bool {
        ($name:ident, $feature:literal) => {
            #[cfg(feature = $feature)]
            macro_rules! $name {
                () => {
                    "true"
                };
            }
            #[cfg(not(feature = $feature))]
            macro_rules! $name {
                () => {
                    "false"
                };
            }
        };
    }

    feature_bool!(feature_mmap, "mmap");
    feature_bool!(feature_sendfile, "sendfile");
    feature_bool!(feature_splice, "splice");
    feature_bool!(feature_ktls, "ktls");

    if version {
        concat!(
            env!("CARGO_PKG_VERSION"),
            "\n",
            "TLS=",
            feature_tls!(),
            "\n",
            "mmap=",
            feature_mmap!(),
            "\n",
            "sendfile=",
            feature_sendfile!(),
            "\n",
            "splice=",
            feature_splice!(),
            "\n",
            "ktls=",
            feature_ktls!(),
        )
    } else {
        concat!(
            "TLS=",
            feature_tls!(),
            "\n",
            "mmap=",
            feature_mmap!(),
            "\n",
            "sendfile=",
            feature_sendfile!(),
            "\n",
            "splice=",
            feature_splice!(),
            "\n",
            "ktls=",
            feature_ktls!(),
        )
    }
}

#[derive(Parser)]
#[command(author, version, long_version(get_features(true)), about)]
struct Cli {
    /// Log file path (log to file instead of console [default])
    #[arg(long, value_name = "PATH")]
    log_file: Option<config::LogDestination>,
    /// Logging level
    #[arg(short, long, value_name = "SEVERITY")]
    log_level: Option<tracing::level_filters::LevelFilter>,
    /// Configuration file path
    #[arg(
        short = 'c',
        long,
        default_value = config::DEFAULT_CONFIGURATION_PATH,
        alias = "config_path",
        value_name = "PATH"
    )]
    config_file: PathBuf,
    /// Cache directory path; overrides `cache_directory` from the
    /// configuration file (or the built-in default when no file is loaded)
    #[arg(long, value_name = "PATH")]
    cache_path: Option<PathBuf>,
    /// Database file path; overrides `database_path` from the configuration
    /// file (or the built-in default when no file is loaded)
    #[arg(long, value_name = "PATH")]
    database_path: Option<PathBuf>,
    /// Skip timestamp in log messages
    #[arg(long, default_value = "false")]
    skip_log_timestamp: bool,
    /// Permit daemon running as root user (potentially dangerous)
    #[arg(long, default_value = "false")]
    permit_running_daemon_as_root: bool,
}

#[derive(Debug)]
struct RuntimeDetails {
    start_time: time::OffsetDateTime,
    config: config::Config,
    cache_quota: cache_quota::CacheQuota,
    checksum_registry: integrity::ChecksumRegistry,
    verify_throttle: verify_throttle::VerifyThrottle,
}

#[derive(Clone, Debug)]
struct ReopenableLogFile {
    path: PathBuf,
    file: Arc<parking_lot::Mutex<std::fs::File>>,
    reopen_requested: Arc<AtomicBool>,
}

impl ReopenableLogFile {
    fn new(path: &Path) -> std::io::Result<Self> {
        let file = utils::nofollow_options()
            .append(true)
            .create(true)
            .open(path)?;
        Ok(Self {
            path: path.to_path_buf(),
            file: Arc::new(parking_lot::Mutex::new(file)),
            reopen_requested: Arc::new(AtomicBool::new(false)),
        })
    }

    fn reopen(&self) -> std::io::Result<()> {
        let file = utils::nofollow_options()
            .append(true)
            .create(true)
            .open(&self.path)?;
        *self.file.lock() = file;
        Ok(())
    }

    fn request_reopen(&self) {
        self.reopen_requested.store(true, Ordering::Relaxed);
    }
}

impl std::io::Write for ReopenableLogFile {
    #[expect(
        clippy::print_stderr,
        reason = "logger-internal failure, can't log via itself"
    )]
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        /* Deferred here so the swap happens on the single non-blocking worker thread. */
        if self.reopen_requested.swap(false, Ordering::Relaxed)
            && let Err(err) = self.reopen()
        {
            eprintln!(
                "Failed to reopen log file `{}`:  {err}",
                self.path.display()
            );
        }
        std::io::Write::write(&mut *self.file.lock(), buf)
    }

    #[inline]
    fn flush(&mut self) -> std::io::Result<()> {
        std::io::Write::flush(&mut *self.file.lock())
    }
}

#[derive(Copy, Clone, Debug)]
struct UtcTimer;

impl tracing_subscriber::fmt::time::FormatTime for UtcTimer {
    fn format_time(&self, w: &mut tracing_subscriber::fmt::format::Writer<'_>) -> std::fmt::Result {
        let now = time::OffsetDateTime::now_utc();
        let formatted = now.format(&Rfc2822).map_err(|_err| std::fmt::Error)?;
        w.write_str(&formatted)
    }
}

static RUNTIMEDETAILS: OnceLock<RuntimeDetails> = OnceLock::new();
static LOGSTORE: OnceLock<logstore::LogStore> = OnceLock::new();
static OUTPUT_LOG_FILE: OnceLock<ReopenableLogFile> = OnceLock::new();

#[must_use]
#[inline]
pub(crate) fn global_config() -> &'static config::Config {
    &RUNTIMEDETAILS
        .get()
        .expect("Global was initialized in main()")
        .config
}

#[must_use]
#[inline]
pub(crate) fn global_cache_quota() -> &'static cache_quota::CacheQuota {
    &RUNTIMEDETAILS
        .get()
        .expect("Global was initialized in main()")
        .cache_quota
}

#[must_use]
#[inline]
pub(crate) fn global_checksum_registry() -> &'static integrity::ChecksumRegistry {
    &RUNTIMEDETAILS
        .get()
        .expect("Global was initialized in main()")
        .checksum_registry
}

#[must_use]
#[inline]
pub(crate) fn global_verify_throttle() -> &'static verify_throttle::VerifyThrottle {
    &RUNTIMEDETAILS
        .get()
        .expect("Global was initialized in main()")
        .verify_throttle
}

#[cfg(feature = "tls_rustls")]
#[cfg_attr(
    feature = "webpki-roots",
    expect(clippy::unnecessary_wraps, reason = "webpki setup is infallible")
)]
fn build_rustls_client_config()
-> Result<rustls::ClientConfig, Box<dyn std::error::Error + Send + Sync>> {
    /* Set a process wide default crypto provider. */
    //let _ = rustls::crypto::ring::default_provider().install_default();
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("first and sole call should succeed");

    #[cfg(feature = "webpki-roots")]
    let tls_config = {
        let root_store = rustls::RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.into(),
        };

        rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth()
    };

    #[cfg(not(feature = "webpki-roots"))]
    let tls_config = {
        use hyper_rustls::ConfigBuilderExt as _;

        rustls::ClientConfig::builder()
            .with_native_roots()
            .inspect_err(|err| error!("Failed to load native roots:  {}", error::ErrorReport(err)))?
            .with_no_client_auth()
    };

    Ok(tls_config)
}

#[cfg(all(feature = "tls_rustls", feature = "splice"))]
fn init_splice_tls_client_config(tls_config: rustls::ClientConfig) {
    #[cfg(feature = "ktls")]
    {
        // Clone before moving the base config into the Arc below:
        // `ClientConfig::clone` shares the `resumption` session store (an
        // `Arc<ClientSessionMemoryCache>` internally), so session tickets
        // learned via the kTLS config still benefit the plain splice
        // fallback and vice versa. Secret extraction is confined to this
        // kTLS-only clone — only the kTLS setup path hands raw traffic
        // secrets to the kernel.
        let mut ktls_config = tls_config.clone();
        ktls_config.enable_secret_extraction = true;
        splice_conn::KTLS_CLIENT_CONFIG
            .set(Arc::new(ktls_config))
            .expect("function should only be called once");
    }

    splice_conn::TLS_CLIENT_CONFIG
        .set(Arc::new(tls_config))
        .expect("function should only be called once");
}

fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut args = Cli::parse();

    let is_run_as_root = nix::unistd::geteuid().is_root();

    #[expect(clippy::print_stderr, reason = "print to stderr before log setup")]
    if is_run_as_root && !args.permit_running_daemon_as_root {
        eprintln!("Running as root is not recommended and not permitted by default");
        std::process::exit(1);
    }

    tracing_log::LogTracer::init()?;

    let (config, cfg_fallback, config_warnings) = config::Config::new(
        &args.config_file,
        args.cache_path.take(),
        args.database_path.take(),
    )?;

    let output_log_level = args.log_level.unwrap_or(config.log_level);
    let output_log_file = args.log_file.as_ref().unwrap_or(&config.log_file);

    LOGSTORE
        .set(logstore::LogStore::new(config.logstore_capacity))
        .expect("Initial set in main() should succeed");

    SCHEME_CACHE
        .set(parking_lot::RwLock::new(HashMap::new()))
        .expect("Initial set in main() should succeed");

    #[cfg(feature = "ktls")]
    KTLS_BLOCKED
        .set(parking_lot::RwLock::new(HashMap::new()))
        .expect("Initial set in main() should succeed");

    #[cfg(feature = "ktls")]
    secure_vec::set_lock_enabled(config.ktls_memory_lock);

    let logstore_handle = LOGSTORE.get().expect("initialized in main()").clone();
    let internal_layer = tracing_subscriber::fmt::layer()
        .with_writer(move || logstore_handle.clone())
        .with_ansi(false)
        .with_target(true)
        .with_thread_names(true)
        .with_level(true)
        .with_timer(UtcTimer)
        .with_filter(tracing::level_filters::LevelFilter::WARN);

    let skip_timestamp = args.skip_log_timestamp;
    // journald prepends its own timestamp
    let skip_stderr_timestamp = skip_timestamp || std::env::var_os("JOURNAL_STREAM").is_some();
    let output_thread_names = output_log_level >= tracing::level_filters::LevelFilter::DEBUG;
    let stderr_is_tty = std::io::stderr().is_terminal();

    let _log_guard: Option<tracing_appender::non_blocking::WorkerGuard> = match output_log_file {
        config::LogDestination::Console => {
            let base = tracing_subscriber::fmt::layer()
                .with_writer(std::io::stderr as fn() -> std::io::Stderr)
                .with_ansi(stderr_is_tty)
                .with_target(false)
                .with_thread_names(output_thread_names)
                .with_level(true);
            let layer = if skip_stderr_timestamp {
                base.without_time().with_filter(output_log_level).boxed()
            } else {
                base.with_timer(UtcTimer)
                    .with_filter(output_log_level)
                    .boxed()
            };
            tracing_subscriber::registry()
                .with(internal_layer)
                .with(layer)
                .init();
            None
        }

        config::LogDestination::File(path) => {
            #[expect(
                clippy::print_stderr,
                reason = "print to stderr for log file open error"
            )]
            let log_file_handle = match ReopenableLogFile::new(path) {
                Ok(file) => file,
                Err(err) if err.raw_os_error() == Some(nix::libc::ELOOP) => {
                    eprintln!(
                        "Failed to open log file `{}`:  {err}; symlinks are not supported",
                        path.display()
                    );
                    std::process::exit(1);
                }
                Err(err) => {
                    eprintln!("Failed to open log file `{}`:  {err}", path.display());
                    std::process::exit(1);
                }
            };
            OUTPUT_LOG_FILE
                .set(log_file_handle.clone())
                .expect("Initial set in main() should succeed");

            let (writer, guard) = tracing_appender::non_blocking::NonBlockingBuilder::default()
                .lossy(false)
                .finish(log_file_handle);

            let base = tracing_subscriber::fmt::layer()
                .with_writer(writer)
                .with_ansi(false)
                .with_target(false)
                .with_thread_names(output_thread_names)
                .with_level(true);
            let layer = if skip_timestamp {
                base.without_time().with_filter(output_log_level).boxed()
            } else {
                base.with_timer(UtcTimer)
                    .with_filter(output_log_level)
                    .boxed()
            };
            tracing_subscriber::registry()
                .with(internal_layer)
                .with(layer)
                .init();
            Some(guard)
        }
    };

    let config_http_timeout = config.http_timeout;

    let checksum_registry = integrity::ChecksumRegistry::new(config.verify_checksums_max_entries);

    // Zeroed base when verification is off: the throttle can never arm, so
    // no call site needs to consult `verify_checksums`.
    let verify_throttle = verify_throttle::VerifyThrottle::new(
        if config.verify_checksums {
            config.verify_checksums_throttle_base
        } else {
            Duration::ZERO
        },
        config.verify_checksums_throttle_cap,
    );

    RUNTIMEDETAILS
        .set(RuntimeDetails {
            start_time: time::OffsetDateTime::now_utc(),
            cache_quota: cache_quota::CacheQuota::new(0, config.disk_quota),
            config,
            checksum_registry,
            verify_throttle,
        })
        .expect("Initial set in main() should succeed");

    debug!("Logger initialized");
    trace!("Tracing enabled");

    #[expect(clippy::print_stderr, reason = "print to stderr for panic hook")]
    std::panic::set_hook(Box::new(move |info| {
        error!("Panic: {info}");
        eprintln!("{info}");
    }));

    if cfg_fallback {
        info!(
            "Default configuration file `{}` not found, using defaults",
            args.config_file.display()
        );
    }

    for warning in config_warnings {
        warn!("Configuration:  {warning}");
    }

    debug!("Configuration: {:?}", global_config());

    if is_run_as_root {
        assert!(
            args.permit_running_daemon_as_root,
            "should not reach if not permitted"
        );
        warn!("!! Running as root is not recommended !!");
    }

    if global_config().allowed_mirrors.is_empty() {
        warn!("No mirror allowed, consider setting option 'allowed_mirrors'");
    }

    info!(
        "Using cache directory `{}`",
        global_config().cache_directory.display()
    );

    task_setup::task_setup().inspect_err(|err| {
        error!("Error during setup:  {err}");
    })?;

    let https_client = {
        // Disable Nagle on upstream connections.  Mirror requests are mostly
        // small headers followed by a long body read, where TCP_NODELAY shaves
        // up to a 40 ms ACK delay off every request.
        let mut tcp_connector = HttpConnector::new();
        tcp_connector.enforce_http(false);
        tcp_connector.set_nodelay(global_config().upstream_tcp_nodelay);

        #[cfg(all(feature = "tls_hyper", not(feature = "tls_rustls")))]
        let https_connector = hyper_tls::HttpsConnector::new_with_connector(tcp_connector);

        #[cfg(feature = "tls_rustls")]
        let https_connector = {
            let tls_config = build_rustls_client_config()?;

            #[cfg(feature = "splice")]
            init_splice_tls_client_config(tls_config.clone());

            hyper_rustls::HttpsConnectorBuilder::new()
                .with_tls_config(tls_config)
                .https_or_http()
                .enable_http1()
                .wrap_connector(tcp_connector)
        };

        let mut timeout_connector = hyper_timeout::TimeoutConnector::new(https_connector);
        // Config validation guarantees 1s <= http_timeout <= 360s, so there
        // is no zero-means-disabled case here.
        debug!("Using http timeout of {config_http_timeout:?}");
        timeout_connector.set_connect_timeout(Some(config_http_timeout));
        timeout_connector.set_read_timeout(Some(config_http_timeout));
        timeout_connector.set_write_timeout(Some(config_http_timeout));

        hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
            .http1_max_headers(limits::MAX_UPSTREAM_HEADERS)
            .build(timeout_connector)
    };

    // Warm the kTLS availability probe before the tokio runtime starts so the
    // one-time socket(2)/bind(2)/listen(2)/connect(2)/accept(2)/setsockopt(2)
    // round-trip never lands on a tokio worker thread.
    #[cfg(feature = "ktls")]
    let _ktls_available = ktls::is_available();

    let runtime = Builder::new_multi_thread()
        .enable_all()
        .thread_name("apt-cacher-rs-w")
        .build()
        .expect("Should succeed");

    drop(args);

    scopeguard::defer! {
        info!("Stopped.");
    }

    runtime.block_on(async { main_loop::main_loop(https_client).await })
}

#[cfg(test)]
mod tests {
    use crate::content_type_for_cached_file;

    #[test]
    fn content_type_for_text_manifests() {
        // Flat-repo debnames (no distribution prefix).
        assert_eq!(content_type_for_cached_file("InRelease"), "text/plain");
        assert_eq!(content_type_for_cached_file("Release"), "text/plain");
        assert_eq!(content_type_for_cached_file("Packages"), "text/plain");
        assert_eq!(content_type_for_cached_file("Sources"), "text/plain");

        // Structured-layout debnames (distribution / component / arch prefixes).
        assert_eq!(content_type_for_cached_file("sid_InRelease"), "text/plain");
        assert_eq!(content_type_for_cached_file("sid_Release"), "text/plain");
        assert_eq!(
            content_type_for_cached_file("sid_main_binary-amd64_Release"),
            "text/plain"
        );
        assert_eq!(
            content_type_for_cached_file("sid_main_binary-amd64_Packages"),
            "text/plain"
        );
        assert_eq!(
            content_type_for_cached_file("sid_main_Sources"),
            "text/plain"
        );
    }

    #[test]
    fn content_type_for_release_gpg() {
        assert_eq!(
            content_type_for_cached_file("Release.gpg"),
            "application/pgp-signature"
        );
        assert_eq!(
            content_type_for_cached_file("sid_Release.gpg"),
            "application/pgp-signature"
        );
    }

    #[test]
    fn compressed_manifest_keeps_compression_content_type() {
        // Compressed manifests must keep their compression Content-Type —
        // the `_Packages` suffix on `Packages.gz` must not coerce it to text.
        assert_eq!(
            content_type_for_cached_file("sid_main_binary-amd64_Packages.gz"),
            "application/gzip"
        );
        assert_eq!(
            content_type_for_cached_file("sid_main_Sources.xz"),
            "application/x-xz"
        );
        assert_eq!(
            content_type_for_cached_file("firefox-esr_115.9.1esr-1_amd64.deb"),
            "application/vnd.debian.binary-package"
        );
        assert_eq!(
            content_type_for_cached_file("unknown_no_extension"),
            "application/octet-stream"
        );
    }
}
