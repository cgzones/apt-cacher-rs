#![allow(
    clippy::too_many_lines,
    reason = "prefer documented and clear structure"
)]

#[cfg(not(any(feature = "hyper", feature = "splice")))]
compile_error!("At least one HTTP backend must be enabled: feature \"hyper\" or \"splice\".");

#[cfg(not(any(feature = "tls_hyper", feature = "tls_rustls")))]
compile_error!("Either feature \"tls_hyper\" or \"tls_rustls\" must be enabled for this crate.");

#[cfg(all(feature = "tls_hyper", feature = "tls_rustls"))]
compile_error!("Feature \"tls_hyper\" and \"tls_rustls\" are mutually exclusive.");

#[cfg(target_env = "musl")]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

#[cfg(feature = "hyper")]
mod accounted_body;
mod active_downloads;
mod build_info;
mod cache_conditional;
mod cache_layout;
mod cache_metadata;
mod cache_paths;
mod cache_quota;
mod cache_walk;
#[cfg(feature = "hyper")]
mod channel_body;
mod cleanup;
mod client_counter;
mod client_info;
mod config;
mod connect_tunnel;
mod content_type;
mod database;
mod database_task;
mod deb_mirror;
mod delivery;
mod error;
mod flat_blocklist;
mod guards;
mod healthcheck;
mod http_etag;
#[cfg(feature = "sendfile")]
mod http_helpers;
mod http_last_modified;
mod http_range;
mod humanfmt;
#[cfg(feature = "hyper")]
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
#[cfg(all(feature = "mmap", feature = "hyper"))]
mod mmap_body;
mod permitted_host_cache;
mod precise_instant;
mod proxy_body;
#[cfg(feature = "hyper")]
mod rate_checked_body;
mod rate_checker;
mod rate_log;
mod request_dispatch;
mod response_head;
mod ringbuffer;
mod scheme_cache;
#[cfg(feature = "ktls")]
mod secure_vec;
#[cfg(feature = "sendfile")]
mod sendfile_conn;
mod small_vec_deque;
#[cfg(feature = "splice")]
mod splice;
mod string_write;
mod task_cache_scan;
mod task_setup;
#[cfg(feature = "splice")]
mod tcp_cork_guard;
#[cfg(test)]
mod test_support;
mod tunnel_limiter;
mod uncacheables;
mod upstream_head;
mod upstream_retry;
mod utils;
mod verify_throttle;
mod web;
mod xattr_helpers;
mod xz_stream;

use std::{
    fmt::Debug,
    io::IsTerminal as _,
    path::{Path, PathBuf},
    sync::{
        Arc, OnceLock,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use build_info::{APP_VERSION, get_features};
use clap::Parser;
#[cfg(feature = "ktls")]
use hashbrown::HashMap;
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

/// Maximum time to wait for the database task to drain on shutdown before giving up.
const DB_DRAIN_TIMEOUT: Duration = Duration::from_secs(15);

pub(crate) use scheme_cache::Scheme;
#[cfg(feature = "ktls")]
pub(crate) use scheme_cache::{SchemeKey, SchemeKeyRef};

#[cfg(feature = "ktls")]
pub(crate) static KTLS_BLOCKED: OnceLock<
    parking_lot::RwLock<HashMap<SchemeKey, coarsetime::Instant>>,
> = OnceLock::new();

#[derive(Clone)]
pub(crate) struct AppState {
    pub(crate) database: database::Database,
    #[cfg(feature = "hyper")]
    pub(crate) https_client: hyper_conn::HttpClient,
    pub(crate) active_downloads: active_downloads::ActiveDownloads,
}

#[derive(Parser)]
#[command(author, version, long_version(get_features(true)), about)]
struct Cli {
    /// Log file path (log to file instead of console, the default)
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
    /// Listening address and/or port (`ADDR`, `ADDR:PORT` or `:PORT`);
    /// overrides `bind_addr`/`bind_port` from the configuration file (or the
    /// built-in defaults when no file is loaded)
    #[arg(long, value_name = "ADDR[:PORT]")]
    bind: Option<config::BindOverride>,
    /// Skip timestamp in log messages (e.g. under systemd/journald, which
    /// prepends its own)
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
                "Failed to reopen log file `{}`; continuing to write to the previously opened file:  {}",
                self.path.display(),
                error::ErrorReport(&err)
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

/// Why the native root CA store could not be assembled.
#[cfg(all(feature = "tls_rustls", not(feature = "webpki-roots")))]
#[derive(Debug, thiserror::Error)]
enum RootStoreError {
    /// No native root CA source yielded a certificate; `errors` counts the
    /// sources that failed to load (each already warned about).
    #[error("no native root CA certificates found ({errors} errors)")]
    NoCertificates { errors: usize },
    /// Certificates were found but none parsed.
    #[error("no valid native root CA certificates found ({invalid} invalid)")]
    NoValidCertificates { invalid: usize },
}

/// The bundled webpki roots cannot fail to load.
#[cfg(all(feature = "tls_rustls", feature = "webpki-roots"))]
type RootStoreError = std::convert::Infallible;

#[cfg(feature = "tls_rustls")]
#[cfg_attr(
    feature = "webpki-roots",
    expect(clippy::unnecessary_wraps, reason = "webpki setup is infallible")
)]
fn build_rustls_client_config() -> Result<rustls::ClientConfig, RootStoreError> {
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
        let result = rustls_native_certs::load_native_certs();
        for err in &result.errors {
            warn!(
                "Failed to load a native root CA source; continuing with the roots that did load:  {}",
                error::ErrorReport(err)
            );
        }
        if result.certs.is_empty() {
            return Err(RootStoreError::NoCertificates {
                errors: result.errors.len(),
            });
        }

        let mut root_store = rustls::RootCertStore::empty();
        let (valid, invalid) = root_store.add_parsable_certificates(result.certs);
        debug!("Loaded {valid} native root CA certificates ({invalid} invalid)");
        if root_store.is_empty() {
            return Err(RootStoreError::NoValidCertificates { invalid });
        }

        rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
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
        splice::KTLS_CLIENT_CONFIG
            .set(Arc::new(ktls_config))
            .expect("function should only be called once");
    }

    splice::TLS_CLIENT_CONFIG
        .set(Arc::new(tls_config))
        .expect("function should only be called once");
}

#[expect(clippy::print_stderr, reason = "logging may not be set up yet")]
fn main() -> std::process::ExitCode {
    match run() {
        Ok(code) => code,
        Err(err) => {
            // Not `error!`: a failure before logging is initialised (config
            // load) would otherwise be swallowed entirely.  `ErrorReport`
            // walks `source()`, which the default `Debug` print would not.
            eprintln!(
                "Failed to run apt-cacher-rs:  {}",
                error::ErrorReport(&*err)
            );
            std::process::ExitCode::FAILURE
        }
    }
}

fn run() -> Result<std::process::ExitCode, Box<dyn std::error::Error + Send + Sync>> {
    struct Stopped;
    impl Drop for Stopped {
        fn drop(&mut self) {
            info!("Stopped");
        }
    }

    let mut args = Cli::parse();

    let is_run_as_root = nix::unistd::geteuid().is_root();

    #[expect(clippy::print_stderr, reason = "print to stderr before log setup")]
    if is_run_as_root && !args.permit_running_daemon_as_root {
        eprintln!("Running as root is not recommended and not permitted by default");
        return Ok(std::process::ExitCode::FAILURE);
    }

    tracing_log::LogTracer::init()?;

    let (config, cfg_fallback, config_warnings) = config::Config::new(
        &args.config_file,
        args.cache_path.take(),
        args.database_path.take(),
        args.bind.take(),
    )?;

    let output_log_level = args.log_level.unwrap_or(config.log_level);
    let output_log_file = args.log_file.as_ref().unwrap_or(&config.log_file);

    LOGSTORE
        .set(logstore::LogStore::new(config.logstore_capacity))
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
    let output_thread_names = output_log_level >= tracing::level_filters::LevelFilter::DEBUG;
    let stderr_is_tty = std::io::stderr().is_terminal();

    // The `non_blocking` `WorkerGuard` flushes the file appender on drop, so
    // it must outlive every log call: keep it bound here in `main()`, never
    // in a shorter scope.
    let _log_guard: Option<tracing_appender::non_blocking::WorkerGuard> = match output_log_file {
        config::LogDestination::Console => {
            let base = tracing_subscriber::fmt::layer()
                .with_writer(std::io::stderr as fn() -> std::io::Stderr)
                .with_ansi(stderr_is_tty)
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
                        "Failed to open log file `{}` (symlinks are not supported); exiting:  {}",
                        path.display(),
                        error::ErrorReport(&err)
                    );
                    return Ok(std::process::ExitCode::FAILURE);
                }
                Err(err) => {
                    eprintln!(
                        "Failed to open log file `{}`; exiting:  {}",
                        path.display(),
                        error::ErrorReport(&err)
                    );
                    return Ok(std::process::ExitCode::FAILURE);
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

    #[cfg(feature = "hyper")]
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

    // First line of every log: which build is talking. Feature flags decide
    // which backend serves a request (sendfile/splice/hyper) and which TLS
    // stack is used, so a log without them cannot be read confidently.
    info!(
        "apt-cacher-rs {APP_VERSION} ({}) starting...",
        get_features(false).replace('\n', " ")
    );

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
        warn!("Configuration `{}`: {warning}", args.config_file.display());
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
        warn!(
            "Option `allowed_mirrors` is empty; every proxy request is rejected with 403 Unauthorized host until it lists the mirrors this cache should serve"
        );
    }

    info!(
        "Using cache directory `{}`",
        global_config().cache_directory.display()
    );

    let _cache_lock = task_setup::task_setup().inspect_err(|err| {
        error!(
            "Failed to prepare the cache directory; aborting startup:  {}",
            error::ErrorReport(err)
        );
    })?;

    #[cfg(all(feature = "splice", feature = "tls_rustls", not(feature = "hyper")))]
    {
        let tls_config = build_rustls_client_config()?;
        init_splice_tls_client_config(tls_config);
    }

    #[cfg(feature = "hyper")]
    let https_client = {
        // Disable Nagle on upstream connections.  Mirror requests are mostly
        // small headers followed by a long body read, where TCP_NODELAY shaves
        // up to a 40 ms ACK delay off every request.
        let mut tcp_connector = hyper_util::client::legacy::connect::HttpConnector::new();
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

    let _guard = Stopped;

    let result = {
        #[cfg(feature = "hyper")]
        {
            runtime.block_on(async { main_loop::main_loop(https_client).await })
        }
        #[cfg(not(feature = "hyper"))]
        {
            runtime.block_on(async { main_loop::main_loop().await })
        }
    };

    result
        .map(|()| std::process::ExitCode::SUCCESS)
        .map_err(Into::into)
}
