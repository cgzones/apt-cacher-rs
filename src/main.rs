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
#[cfg(feature = "ktls")]
mod ktls;
#[cfg(feature = "ktls")]
mod ktls_handshake;
mod limits;
mod log_once;
mod logstore;
mod metrics;
#[cfg(feature = "mmap")]
mod mmap_body;
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
mod task_cleanup;
mod task_setup;
#[cfg(feature = "sendfile")]
mod tcp_cork_guard;
mod uncacheables;
mod utils;
mod web_interface;
mod xattr_helpers;
mod xz_stream;

use std::{
    fmt::Debug,
    fmt::Display,
    hash::Hash,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4},
    num::NonZero,
    os::unix::fs::OpenOptionsExt as _,
    path::{Path, PathBuf},
    pin::Pin,
    sync::{Arc, OnceLock},
    time::Duration,
};

use clap::Parser;
use coarsetime::Instant;
use futures_util::StreamExt as _;
use hashbrown::{Equivalent, HashMap};
use http::{
    Method, Request, Response, StatusCode, Uri,
    header::{ALLOW, CONNECTION, CONTENT_TYPE, DATE, SERVER, USER_AGENT, VIA},
};
use http_body::{Body, Frame, SizeHint};
use http_body_util::{BodyExt as _, Empty, Full, combinators::BoxBody};
#[cfg(all(feature = "tls_hyper", not(feature = "tls_rustls")))]
use hyper_tls::HttpsConnector;
use hyper_util::client::legacy::connect::HttpConnector;
use log::{LevelFilter, debug, error, info, trace, warn};
use pin_project::pin_project;
#[cfg(feature = "mmap")]
use rate_checked_body::{MaybeRated, RateCheckedBodyErr};
use simplelog::{
    ColorChoice, CombinedLogger, ConfigBuilder, TermLogger, TerminalMode, WriteLogger,
};
use tokio::{net::TcpListener, runtime::Builder, signal::unix::SignalKind};

#[cfg(feature = "splice")]
use crate::active_downloads::OriginateOutcome;
use crate::active_downloads::{AbortReason, ActiveDownloadStatus, ActiveDownloads};
use crate::cache_layout::ConnectionDetails;
use crate::config::Config;
use crate::config::HttpsUpgradeMode;
use crate::config::LogDestination;
use crate::database::Database;
use crate::database_task::DbCmdOrigin;
use crate::database_task::db_loop;
use crate::deb_mirror::Mirror;
use crate::deb_mirror::Origin;
use crate::error::ErrorReport;
use crate::error::ProxyCacheError;
use crate::http_range::format_http_date;
use crate::humanfmt::HumanFmt;
use crate::hyper_conn::HttpClient;
use crate::hyper_conn::handle_hyper_connection;
pub(crate) use crate::hyper_conn::process_cache_request;
use crate::hyper_conn::request_with_retry;
use crate::logstore::LogStore;
#[cfg(feature = "mmap")]
use crate::mmap_body::MmapBody;
#[cfg(feature = "mmap")]
use crate::mmap_body::MmapData;
use crate::permitted_host_cache::authorize_cache_access;
use crate::permitted_host_cache::is_host_allowed_cached;
use crate::request_dispatch::{DispatchOutcome, dispatch_request};
use crate::task_cache_scan::task_cache_scan;
use crate::task_cleanup::{
    CLEANUP_INTERVAL_SECS, FIRST_CLEANUP_DELAY_SECS, set_next_cleanup_epoch, task_cleanup,
};
use crate::task_setup::task_setup;
use crate::uncacheables::record_uncacheable;
use crate::web_interface::serve_web_interface;

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
    mirror: &Mirror,
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
const CLEANUP_CLIENT_ADDR: SocketAddr =
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
        .header(DATE, format_http_date())
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
    Mmap(#[pin] MaybeRated<MmapBody>, ClientInfo),
    Boxed(#[pin] BoxBody<bytes::Bytes, Box<ProxyCacheError>>),
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

    type Error = Box<ProxyCacheError>;

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
                        Box::new(ProxyCacheError::ClientDownloadRate {
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
    Mmap(MmapData),
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
    pub(crate) database: Database,
    pub(crate) https_client: HttpClient,
    pub(crate) active_downloads: ActiveDownloads,
}

mod permitted_host_cache {
    use hashbrown::HashMap;
    use http::StatusCode;

    use crate::{ClientInfo, config::ClientHost, global_config, metrics, warn_once_or_info};

    #[must_use]
    fn is_host_allowed(requested_host: &str) -> bool {
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

    /// Reason a `Host:` header was rejected by [`authorize_cache_access`];
    /// cached so repeat-spam of the same bad host doesn't re-validate or
    /// re-scan `allowed_mirrors`.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum HostReject {
        /// Failed `ClientHost::new` — malformed `Host:` header.
        Unsupported,
        /// Validated, but not permitted by `allowed_mirrors`.
        Forbidden,
    }

    /// Caches the full validation + allow-list check result per raw `Host:`
    /// string.  On hit, [`authorize_cache_access`] returns a cloned
    /// `ClientHost` without re-running `ClientHost::new` or scanning
    /// `allowed_mirrors`.
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

    static PERMITTED_HOST_CACHE: std::sync::LazyLock<PermittedHostCache> =
        std::sync::LazyLock::new(PermittedHostCache::default);

    /// Cache-aware companion to [`is_host_allowed`] for the moved-host /
    /// redirect-destination call sites.  On a hit, returns the cached
    /// allow/deny result without re-scanning `allowed_mirrors`.  On a
    /// miss, falls through to the uncached scan (these call sites don't
    /// have a `ClientHost` to store, so we don't populate the cache here
    /// — only [`authorize_cache_access`] does).
    #[must_use]
    pub(crate) fn is_host_allowed_cached(requested_host: &str) -> bool {
        if let Some(cached) = PERMITTED_HOST_CACHE.lookup(requested_host) {
            return cached.is_ok();
        }
        is_host_allowed(requested_host)
    }

    pub(crate) fn authorize_cache_access(
        client: &ClientInfo,
        requested_host: &str,
    ) -> Result<ClientHost, (http::StatusCode, &'static str)> {
        let config = global_config();

        let allowed_proxy_clients = config.allowed_proxy_clients.as_slice();
        let client_ip = client.ip();
        if !allowed_proxy_clients.is_empty()
            && !allowed_proxy_clients
                .iter()
                .any(|ac| ac.contains(&client_ip))
        {
            warn_once_or_info!("Unauthorized proxy client {client}");
            metrics::AUTHZ_REJECTED_CLIENT.increment();
            return Err((StatusCode::FORBIDDEN, "Unauthorized client"));
        }

        // Hot path: cache hit returns a cloned ClientHost without
        // re-validating or rescanning allowed_mirrors.
        if let Some(cached) = PERMITTED_HOST_CACHE.lookup(requested_host) {
            return finalize_host_result(cached, requested_host);
        }

        // Miss: validate the host and check allowed_mirrors, then cache
        // whatever the outcome was (success, malformed, or not-allowed).
        // `ClientHost::new` consumes its argument, so we hand it an owned
        // copy and reuse the original `&str` for the cache key.
        let result = match ClientHost::new(requested_host.to_owned()) {
            Ok(c) if is_host_allowed(&c) => Ok(c),
            Ok(_) => Err(HostReject::Forbidden),
            Err(_) => Err(HostReject::Unsupported),
        };
        PERMITTED_HOST_CACHE.insert(requested_host.into(), result.clone());
        finalize_host_result(result, requested_host)
    }

    fn finalize_host_result(
        result: Result<ClientHost, HostReject>,
        raw_host: &str,
    ) -> Result<ClientHost, (http::StatusCode, &'static str)> {
        match result {
            Ok(d) => Ok(d),
            Err(HostReject::Unsupported) => {
                warn_once_or_info!("Unsupported host `{}`", raw_host.escape_debug());
                Err((StatusCode::BAD_REQUEST, "Unsupported host"))
            }
            Err(HostReject::Forbidden) => {
                warn_once_or_info!("Unauthorized host `{}`", raw_host.escape_debug());
                metrics::AUTHZ_REJECTED_MIRROR.increment();
                Err((StatusCode::FORBIDDEN, "Unauthorized host"))
            }
        }
    }
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

pub(crate) mod client_counter {
    use std::net::IpAddr;
    use std::num::NonZero;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use hashbrown::HashMap;

    use crate::metrics;

    static CONNECTED_CLIENTS: AtomicUsize = AtomicUsize::new(0);
    static CLIENT_DOWNLOADS: AtomicUsize = AtomicUsize::new(0);

    static CONNECTIONS_PER_IP: std::sync::LazyLock<parking_lot::Mutex<HashMap<IpAddr, usize>>> =
        std::sync::LazyLock::new(|| parking_lot::Mutex::new(HashMap::new()));

    #[must_use]
    pub(crate) fn connected_clients() -> usize {
        CONNECTED_CLIENTS.load(Ordering::Relaxed)
    }

    pub(crate) struct ClientCounter {
        client_ip: IpAddr,
        /// `true` iff `try_new` inserted/incremented an entry in
        /// `CONNECTIONS_PER_IP`. When `false`, `Drop` skips the mutex
        /// acquire entirely — the no-cap deployment path is then a single
        /// atomic decrement.
        tracked_per_ip: bool,
    }

    impl ClientCounter {
        pub(crate) fn try_new(
            client_ip: IpAddr,
            max_per_ip: Option<NonZero<usize>>,
        ) -> Option<Self> {
            let tracked_per_ip = if let Some(max) = max_per_ip {
                let mut map = CONNECTIONS_PER_IP.lock();
                let count = map.entry(client_ip).or_insert(0);
                if *count >= max.get() {
                    drop(map);
                    metrics::CONNECTION_REJECTED_PER_IP_CAP.increment();
                    return None;
                }
                *count += 1;
                let observed = *count as u64;
                drop(map);
                metrics::PER_CLIENT_IP_PEAK.update(observed);
                true
            } else {
                false
            };
            let current = CONNECTED_CLIENTS.fetch_add(1, Ordering::Relaxed) + 1;
            metrics::CONNECTED_CLIENTS_PEAK.update(current as u64);
            Some(Self {
                client_ip,
                tracked_per_ip,
            })
        }
    }

    impl Drop for ClientCounter {
        fn drop(&mut self) {
            CONNECTED_CLIENTS.fetch_sub(1, Ordering::Relaxed);
            if !self.tracked_per_ip {
                return;
            }
            let mut map = CONNECTIONS_PER_IP.lock();
            if let hashbrown::hash_map::Entry::Occupied(mut entry) = map.entry(self.client_ip) {
                let count = entry.get_mut();
                *count -= 1;
                if *count == 0 {
                    entry.remove();
                }
            }
        }
    }

    #[must_use]
    pub(crate) fn active_client_downloads() -> usize {
        CLIENT_DOWNLOADS.load(Ordering::Relaxed)
    }

    #[derive(Debug)]
    pub(crate) struct ClientDownload {
        _private: (),
    }

    impl ClientDownload {
        pub(crate) fn new() -> Self {
            let current = CLIENT_DOWNLOADS.fetch_add(1, Ordering::Relaxed) + 1;
            metrics::ACTIVE_CLIENT_DOWNLOADS_PEAK.update(current as u64);
            Self { _private: () }
        }
    }

    impl Drop for ClientDownload {
        fn drop(&mut self) {
            CLIENT_DOWNLOADS.fetch_sub(1, Ordering::Relaxed);
        }
    }
}

async fn main_loop(
    https_client: HttpClient,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let config = global_config();

    let database = Database::connect(&config.database_path, config.database_slow_timeout)
        .await
        .inspect_err(|err| {
            error!(
                "Error creating database `{}`:  {err}",
                config.database_path.display()
            );
        })?;

    database.init_tables().await.inspect_err(|err| {
        error!(
            "Error initializing database `{}`:  {err}",
            config.database_path.display()
        );
    })?;

    database.cleanup_invalid_rows().await.inspect_err(|err| {
        error!("Failed to clean up invalid database rows:  {err}");
    })?;

    // Seed the per-host flat-layout collision blocklist from any
    // pre-existing structured mirrors whose `mirror_path` starts with
    // `flat/` (or equals `flat`).  Those hosts get flat caching disabled
    // — see `flat_blocklist` for the rationale.
    //
    // Both failure modes here are startup-fatal: a DB read error would
    // leave the blocklist empty and silently re-allow flat caching at
    // collision sites, and a double-init is a programmer error in main-
    // loop ordering.  `.expect` panics with `{msg}: {err:?}`, so the
    // panic line surfaces the specific `InitFailure` variant alongside
    // the message (the DB error itself has already been logged inside
    // `init`).
    flat_blocklist::init(&database).await.inspect_err(|err| {
        error!("Failed to load flat-collision mirrors at startup:  {err}");
    })?;

    // Database background task
    let (db_task_tx, db_task_rx) = tokio::sync::mpsc::channel(config.db_channel_capacity.get());
    let (db_shutdown_tx, db_shutdown_rx) = tokio::sync::watch::channel(false);
    let db_join = {
        let database = database.clone();
        let flush_max_count = config.db_batch_flush_max_count.get();
        let flush_interval = Duration::from_secs(config.db_batch_flush_interval_secs.get());
        tokio::task::spawn(db_loop(
            database,
            db_task_rx,
            db_shutdown_rx,
            flush_max_count,
            flush_interval,
        ))
    };
    database_task::DB_TASK_QUEUE_SENDER
        .set(db_task_tx)
        .expect("DB task queue sender initialized once");

    // Process-local cache for cached-file ETag / Last-Modified xattrs.
    cache_metadata::init().expect("cache metadata store initialized once");

    // Migration warning: scan the existing `mirrors_v2` rows for paths
    // containing a `RESERVED_MIRROR_PATH_SEGMENTS` segment.  Pre-existing
    // rows still load via `get_mirrors`, but the validator now rejects
    // them on insert — flag them once at startup so an operator can
    // investigate (cleanup walks against e.g. `<host>/by-hash` would
    // otherwise collide with the layout plumbing for that mirror's
    // sibling).
    let mirrors = database.get_mirrors().await.inspect_err(|err| {
        error!("Failed to scan mirrors for reserved-segment migration warning:  {err}");
    })?;

    for mirror in &mirrors {
        if deb_mirror::mirror_path_has_reserved_segment(&mirror.path) {
            warn!(
                "Pre-existing mirror row `{}/{}` uses a reserved path segment (one of {:?}); cleanup walks may collide with cache plumbing - investigate and consider removing the row",
                mirror.host,
                mirror.path,
                deb_mirror::RESERVED_MIRROR_PATH_SEGMENTS,
            );
        }
    }

    // Migration warning: the pre-fix flat layout cached every flat-repo
    // file under `<cache>/<host>/<mirror_path>/flat/...`.  Post-fix lookups
    // go to `<cache>/<host>/flat/<mirror_path>/...`, so those legacy
    // directories are now unreachable disk waste.  Probe each registered
    // mirror's legacy flat dir and warn so the operator can reclaim
    // space; we deliberately do not remove anything automatically because
    // a misconfigured alias change could otherwise wipe live cache.
    for mirror in &mirrors {
        let legacy_flat = config
            .cache_directory
            .join(mirror.cache_host().format_cache_dir(mirror.port()).as_ref())
            .join(&mirror.path)
            .join(cache_layout::SUBDIR_FLAT);
        match tokio::fs::symlink_metadata(&legacy_flat).await {
            Ok(md) if md.file_type().is_dir() => {
                warn!(
                    "Legacy pre-fix flat cache directory `{}` is now unreachable (flat files moved to `<host>/flat/<mirror_path>/`); inspect and remove to reclaim disk space",
                    legacy_flat.display(),
                );
            }
            Ok(_) | Err(_) => {}
        }
    }

    // Initial cache scan task
    {
        let database = database.clone();
        tokio::task::spawn(async move {
            match task_cache_scan(&database).await {
                Ok(cache_size) => {
                    let rd = RUNTIMEDETAILS.get().expect("global set in main()");

                    rd.cache_quota.add(cache_size);

                    match rd.config.disk_quota {
                        Some(val) => {
                            let val = val.get();
                            if cache_size > val {
                                warn!(
                                    "Startup cache size of {} exceeds quota {}",
                                    HumanFmt::Size(cache_size),
                                    HumanFmt::Size(val)
                                );
                            } else {
                                info!(
                                    "Startup cache size: {} (quota={})",
                                    HumanFmt::Size(cache_size),
                                    HumanFmt::Size(val)
                                );
                            }
                        }
                        None => {
                            info!(
                                "Startup cache size: {} (quota=unlimited)",
                                HumanFmt::Size(cache_size)
                            );
                        }
                    }
                }
                Err(err) => {
                    error!("Startup cache scan failed; cache size unset:  {err}");
                }
            }
        });
    }

    // Scheme cache initialization task

    {
        let database = database.clone();
        let client = https_client.clone();

        tokio::task::spawn(async move {
            // Use buffer_unordered to limit concurrent requests and avoid thundering herd
            const MAX_CONCURRENT_REQUESTS: usize = 10;
            // Do not initialize stale mirrors
            const STALE_THRESHOLD: Duration = Duration::from_hours(30 * 24);

            debug!("Scheme cache initialization task started");

            let mut mirrors = match database.get_recent_mirrors(STALE_THRESHOLD).await {
                Ok(m) => m,
                Err(err) => {
                    metrics::DB_OPERATION_FAILED.increment();
                    error!("Failed to get list of mirrors to initialize scheme cache:  {err}");
                    return;
                }
            };

            mirrors
                .sort_unstable_by(|a, b| a.host.cmp(&b.host).then_with(|| a.port().cmp(&b.port())));
            mirrors.dedup_by(|a, b| a.host == b.host && a.port() == b.port());

            futures_util::stream::iter(mirrors)
                .map(|mirror| {
                    let client = client.clone();
                    async move {
                        let authority = mirror.format_authority();

                        let uri = Uri::builder()
                            .scheme("http")
                            .authority(authority.as_ref())
                            .path_and_query("/")
                            .build()
                            .expect("Valid URI");

                        let request = Request::builder()
                            .method(Method::HEAD)
                            .uri(uri)
                            .header(USER_AGENT, APP_USER_AGENT)
                            .body(Empty::new())
                            .expect("Valid request");

                        match request_with_retry(&client, request).await {
                            Ok(response) => {
                                if response.status().is_server_error() {
                                    warn!(
                                        "Initial scheme cache request to host {authority} returned server error {}",
                                        response.status()
                                    );
                                } else {
                                    // ignore response, we just care about connection success
                                    trace!(
                                        "Response for host {authority} of initial scheme cache request:  {response:?}"
                                    );
                                }
                            }
                            Err(err) => {
                                // request_with_retry() has already logged the error
                                debug!("Failed to query host {authority} to initialize scheme cache:  {}", ErrorReport(&err));
                            }
                        }
                    }
                })
                .buffer_unordered(MAX_CONCURRENT_REQUESTS)
                .collect::<Vec<_>>()
                .await;

            trace!(
                "Scheme cache:  {:?}",
                *SCHEME_CACHE.get().expect("initialized in main()").read()
            );

            debug!("Scheme cache initialization task finished");
        });
    }

    let mut term_signal = tokio::signal::unix::signal(SignalKind::terminate())?;
    let mut usr1_signal = tokio::signal::unix::signal(SignalKind::user_defined1())?;
    let mut usr2_signal = tokio::signal::unix::signal(SignalKind::user_defined2())?;

    // The displayed "Next Cleanup" epoch is advanced from now() on each tick;
    // the underlying Tokio interval schedules from the original baseline
    // instead, so under sustained backpressure the displayed value can drift
    // a few seconds ahead of the real next tick. Accepted limitation.
    let first_cleanup = tokio::time::Instant::now() + Duration::from_secs(FIRST_CLEANUP_DELAY_SECS);
    let mut cleanup_interval =
        tokio::time::interval_at(first_cleanup, Duration::from_secs(CLEANUP_INTERVAL_SECS));
    set_next_cleanup_epoch(
        time::OffsetDateTime::now_utc().unix_timestamp()
            + i64::try_from(FIRST_CLEANUP_DELAY_SECS)
                .expect("FIRST_CLEANUP_DELAY_SECS fits in i64"),
    );

    let appstate = AppState {
        database,
        https_client,
        active_downloads: ActiveDownloads::new(),
    };

    let mut addr = SocketAddr::from((config.bind_addr, config.bind_port.get()));

    let listener = match TcpListener::bind(addr).await {
        Ok(x) => x,
        Err(err) => {
            if config.bind_addr != Ipv6Addr::UNSPECIFIED {
                error!("Error binding on {addr}:  {}", ErrorReport(&err));
                return Err(err.into());
            }

            // Fallback to IPv4 to avoid errors when IPv6 is not available and the default configuration is used.
            addr = SocketAddr::from((Ipv4Addr::UNSPECIFIED, config.bind_port.get()));
            TcpListener::bind(addr).await.inspect_err(|err| {
                error!("Error binding fallback on {addr}:  {}", ErrorReport(err));
            })?
        }
    };
    info!("Ready and listening on http://{addr}");

    let drain_db_task = async move {
        if db_shutdown_tx.send(true).is_err() {
            warn!("Database task already exited before shutdown signal");
        }
        match tokio::time::timeout(DB_DRAIN_TIMEOUT, db_join).await {
            Ok(Ok(())) => {}
            Ok(Err(err)) => error!("Database task did not exit cleanly:  {err}"),
            Err(_) => error!(
                "Database task did not drain within {} seconds, abandoning",
                DB_DRAIN_TIMEOUT.as_secs()
            ),
        }
    };
    tokio::pin!(drain_db_task);

    loop {
        trace!(
            "Active downloads ({}):  {:?}",
            appstate.active_downloads.len(),
            appstate.active_downloads
        );

        let next = tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                info!("SIGINT received, stopping...");
                drain_db_task.as_mut().await;
                return Ok(());
            },
            _ = term_signal.recv() => {
                info!("SIGTERM received, stopping...");
                drain_db_task.as_mut().await;
                return Ok(());
            },
            _ = cleanup_interval.tick() => {
                info!("Daily cleanup issued...");
                set_next_cleanup_epoch(
                    time::OffsetDateTime::now_utc().unix_timestamp()
                        + i64::try_from(CLEANUP_INTERVAL_SECS).expect("CLEANUP_INTERVAL_SECS fits in i64"),
                );
                let appstate = appstate.clone();
                tokio::task::spawn(async move {
                    if let Err(err) = task_cleanup(&appstate).await {
                        error!("Failed to perform daily cleanup task:  {err}");
                    }
                });
                continue;
            },
            _ = usr1_signal.recv() => {
                if let Some(output_log_file) = OUTPUT_LOG_FILE.get() {
                    info!("SIGUSR1 received, reopening log file `{}`...", output_log_file.path.display());
                    let res = tokio::task::block_in_place(|| output_log_file.reopen());
                    match res {
                        Ok(()) => info!("Log file `{}` reopened", output_log_file.path.display()),
                        Err(err) => error!(
                            "Failed to reopen log file `{}`:  {}",
                            output_log_file.path.display(),
                            ErrorReport(&err)
                        ),
                    }
                } else {
                    info!("Ignoring SIGUSR1 because logging is set to console");
                }
                continue;
            },
            _ = usr2_signal.recv() => {
                info!("SIGUSR2 received, issuing cleanup...");
                cleanup_interval.reset();
                set_next_cleanup_epoch(
                    time::OffsetDateTime::now_utc().unix_timestamp()
                        + i64::try_from(CLEANUP_INTERVAL_SECS).expect("CLEANUP_INTERVAL_SECS fits in i64"),
                );
                let appstate = appstate.clone();
                tokio::task::spawn(async move {
                    if let Err(err) = task_cleanup(&appstate).await {
                        error!("Failed to perform SIGUSR2-triggered cleanup task:  {err}");
                    }
                });
                continue;
            },
            n = listener.accept() => n
        };

        let (stream, client) = next
            .map(|(stream, client)| (stream, ClientInfo::new(client)))
            .inspect_err(|err| {
                error!("Error accepting connection:  {}", ErrorReport(err));
            })?;

        metrics::CONNECTIONS_ACCEPTED.increment();

        let Some(client_counter) = client_counter::ClientCounter::try_new(
            client.ip(),
            config.max_connections_per_client_ip,
        ) else {
            info!(
                "Rejecting connection from client {client}: \
                 per-client-IP connection limit ({}) reached",
                config
                    .max_connections_per_client_ip
                    .expect("limit reached implies a configured cap")
            );
            // Drop the stream; closing the socket is the cheapest available
            // signal — sending a 503 would itself be subject to the same load.
            drop(stream);
            continue;
        };

        debug!("New client connection from {client}");
        let client_start = Instant::now();

        let appstate = appstate.clone();
        tokio::task::spawn(async move {
            #[cfg(feature = "sendfile")]
            sendfile_conn::handle_sendfile_connection(stream, client, appstate).await;

            #[cfg(not(feature = "sendfile"))]
            handle_hyper_connection(stream, client, appstate).await;

            debug!(
                "Closed connection to client {client} after {}",
                HumanFmt::Time(client_start.elapsed().into())
            );

            drop(client_counter);
        });
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
    log_file: Option<LogDestination>,
    /// Logging level
    #[arg(short, long, value_name = "SEVERITY")]
    log_level: Option<LevelFilter>,
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
    config: Config,
    cache_quota: cache_quota::CacheQuota,
}

#[derive(Clone, Debug)]
struct ReopenableLogFile {
    path: PathBuf,
    file: Arc<parking_lot::Mutex<std::fs::File>>,
}

impl ReopenableLogFile {
    fn new(path: &Path) -> std::io::Result<Self> {
        let file = std::fs::File::options()
            .append(true)
            .create(true)
            .custom_flags(nix::libc::O_NOFOLLOW)
            .open(path)?;
        Ok(Self {
            path: path.to_path_buf(),
            file: Arc::new(parking_lot::Mutex::new(file)),
        })
    }

    fn reopen(&self) -> std::io::Result<()> {
        let file = std::fs::File::options()
            .append(true)
            .create(true)
            .custom_flags(nix::libc::O_NOFOLLOW)
            .open(&self.path)?;
        *self.file.lock() = file;
        Ok(())
    }
}

impl std::io::Write for ReopenableLogFile {
    #[inline]
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        std::io::Write::write(&mut *self.file.lock(), buf)
    }

    #[inline]
    fn flush(&mut self) -> std::io::Result<()> {
        std::io::Write::flush(&mut *self.file.lock())
    }
}

static RUNTIMEDETAILS: OnceLock<RuntimeDetails> = OnceLock::new();
static LOGSTORE: OnceLock<LogStore> = OnceLock::new();
static OUTPUT_LOG_FILE: OnceLock<ReopenableLogFile> = OnceLock::new();

#[must_use]
#[inline]
pub(crate) fn global_config() -> &'static Config {
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

fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut args = Cli::parse();

    let is_run_as_root = nix::unistd::geteuid().is_root();

    #[expect(clippy::print_stderr, reason = "print to stderr before log setup")]
    if is_run_as_root && !args.permit_running_daemon_as_root {
        eprintln!("Running as root is not recommended and not permitted by default");
        std::process::exit(1);
    }

    let (config, cfg_fallback, config_warnings) = Config::new(
        &args.config_file,
        args.cache_path.take(),
        args.database_path.take(),
    )?;

    let output_log_level = args.log_level.unwrap_or(config.log_level);
    let output_log_file = args.log_file.as_ref().unwrap_or(&config.log_file);

    let output_log_config = ConfigBuilder::new()
        .set_time_level(if args.skip_log_timestamp {
            LevelFilter::Off
        } else {
            LevelFilter::Error
        })
        .set_thread_level(if output_log_level >= LevelFilter::Debug {
            LevelFilter::Error
        } else {
            LevelFilter::Off
        })
        .build();

    let internal_log_config = ConfigBuilder::new()
        .set_location_level(LevelFilter::Error)
        .set_level_padding(simplelog::LevelPadding::Right)
        .set_target_level(LevelFilter::Warn)
        .set_thread_level(LevelFilter::Error)
        .set_thread_mode(simplelog::ThreadLogMode::Names)
        .set_time_format_rfc2822()
        .build();

    LOGSTORE
        .set(LogStore::new(config.logstore_capacity))
        .expect("Initial set in main() should succeed");

    SCHEME_CACHE
        .set(parking_lot::RwLock::new(HashMap::new()))
        .expect("Initial set in main() should succeed");

    #[cfg(feature = "ktls")]
    KTLS_BLOCKED
        .set(parking_lot::RwLock::new(HashMap::new()))
        .expect("Initial set in main() should succeed");

    let internal_logger = WriteLogger::new(
        LevelFilter::Warn,
        internal_log_config,
        LOGSTORE.get().expect("initialized in main()").clone(),
    );

    match output_log_file {
        LogDestination::Console => {
            CombinedLogger::init(vec![
                TermLogger::new(
                    output_log_level,
                    output_log_config,
                    TerminalMode::Mixed,
                    ColorChoice::Auto,
                ),
                internal_logger,
            ])?;
        }

        LogDestination::File(path) => {
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

            CombinedLogger::init(vec![
                WriteLogger::new(output_log_level, output_log_config, log_file_handle),
                internal_logger,
            ])?;
        }
    }

    let config_http_timeout = config.http_timeout;

    RUNTIMEDETAILS
        .set(RuntimeDetails {
            start_time: time::OffsetDateTime::now_utc(),
            cache_quota: cache_quota::CacheQuota::new(0, config.disk_quota),
            config,
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

    task_setup().inspect_err(|err| {
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
        let https_connector = HttpsConnector::new_with_connector(tcp_connector);

        #[cfg(feature = "tls_rustls")]
        let https_connector = {
            use hyper_rustls::ConfigBuilderExt as _;

            /* Set a process wide default crypto provider. */
            //let _ = rustls::crypto::ring::default_provider().install_default();
            rustls::crypto::aws_lc_rs::default_provider()
                .install_default()
                .expect("first and sole call should succeed");

            #[cfg(feature = "webpki-roots")]
            let tls_config = rustls::ClientConfig::builder()
                .with_webpki_roots()
                .with_no_client_auth();
            #[cfg(not(feature = "webpki-roots"))]
            let tls_config = rustls::ClientConfig::builder()
                .with_native_roots()
                .inspect_err(|err| error!("Failed to load native roots:  {}", ErrorReport(err)))?
                .with_no_client_auth();

            #[cfg(feature = "splice")]
            {
                #[cfg_attr(
                    not(feature = "ktls"),
                    expect(unused_mut, reason = "kTLS needs to extract secret")
                )]
                let mut tls_config_splice = tls_config.clone();

                #[cfg(feature = "ktls")]
                {
                    tls_config_splice.enable_secret_extraction = true;
                }

                splice_conn::TLS_CLIENT_CONFIG
                    .set(Arc::new(tls_config_splice))
                    .expect("function should only be called once");
            }

            hyper_rustls::HttpsConnectorBuilder::new()
                .with_tls_config(tls_config)
                .https_or_http()
                .enable_http1()
                .wrap_connector(tcp_connector)
        };

        let mut timeout_connector = hyper_timeout::TimeoutConnector::new(https_connector);
        let http_timeout = match config_http_timeout {
            x if x.is_zero() => None,
            x => Some(x),
        };
        debug!("Using http timeout of {http_timeout:?}");
        timeout_connector.set_connect_timeout(http_timeout);
        timeout_connector.set_read_timeout(http_timeout);
        timeout_connector.set_write_timeout(http_timeout);

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

    runtime.block_on(async { main_loop(https_client).await })
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
