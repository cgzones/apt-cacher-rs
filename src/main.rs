#![cfg_attr(not(any(feature = "mmap", feature = "sendfile")), forbid(unsafe_code))]
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

mod cache_quota;
mod channel_body;
mod config;
mod database;
mod database_task;
mod deb_mirror;
mod error;
mod guards;
mod http_etag;
mod http_range;
mod humanfmt;
mod log_once;
mod logstore;
mod rate_checked_body;
mod ringbuffer;
#[cfg(feature = "sendfile")]
mod sendfile_conn;
mod task_cache_scan;
mod task_cleanup;
mod task_setup;
mod utils;
mod web_interface;

use std::convert::Infallible;
use std::error::Error as _;
use std::fmt::Debug;
use std::fmt::Display;
use std::fs::OpenOptions;
use std::hash::Hash;
use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::num::NonZero;
use std::os::unix::fs::MetadataExt as _;
use std::path::Path;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::OnceLock;
use std::task::Poll::Pending;
use std::task::Poll::Ready;
use std::time::Duration;
use std::time::SystemTime;

use channel_body::ChannelBody;
use channel_body::ChannelBodyError;
use clap::Parser;
use coarsetime::Instant;
use futures_util::StreamExt as _;
use futures_util::TryStreamExt as _;
use hashbrown::hash_map::Entry;
use hashbrown::{Equivalent, HashMap, hash_map::EntryRef};
use http_body_util::{BodyExt as _, Empty, Full, combinators::BoxBody};
use http_range::http_parse_range;
use hyper::Uri;
use hyper::body::Frame;
use hyper::body::Incoming;
use hyper::body::SizeHint;
use hyper::header::ACCEPT;
use hyper::header::ACCEPT_RANGES;
use hyper::header::AGE;
use hyper::header::CACHE_CONTROL;
use hyper::header::CONNECTION;
use hyper::header::CONTENT_LENGTH;
use hyper::header::CONTENT_RANGE;
use hyper::header::CONTENT_TYPE;
use hyper::header::DATE;
use hyper::header::ETAG;
use hyper::header::HOST;
use hyper::header::HeaderName;
use hyper::header::HeaderValue;
use hyper::header::IF_MODIFIED_SINCE;
use hyper::header::IF_NONE_MATCH;
use hyper::header::IF_RANGE;
use hyper::header::LAST_MODIFIED;
use hyper::header::LOCATION;
use hyper::header::RANGE;
use hyper::header::RETRY_AFTER;
use hyper::header::SERVER;
use hyper::header::USER_AGENT;
use hyper::header::VIA;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode, body::Body};
#[cfg(feature = "tls_rustls")]
use hyper_rustls::{ConfigBuilderExt as _, HttpsConnector};
#[cfg(all(feature = "tls_hyper", not(feature = "tls_rustls")))]
use hyper_tls::HttpsConnector;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioIo;
use log::{Level, LevelFilter, debug, error, info, log, trace, warn};
#[cfg(feature = "mmap")]
use memmap2::{Advice, Mmap, MmapOptions};
use pin_project::pin_project;
use pin_project::pinned_drop;
use rand::distr::Bernoulli;
use rand::prelude::Distribution as _;
use rate_checked_body::RateCheckedBody;
use rate_checked_body::RateCheckedBodyErr;
use simplelog::CombinedLogger;
use simplelog::ConfigBuilder;
use simplelog::WriteLogger;
use simplelog::{ColorChoice, TermLogger, TerminalMode};
use tokio::io::AsyncReadExt as _;
use tokio::io::AsyncSeekExt as _;
use tokio::io::AsyncWriteExt as _;
use tokio::net::TcpListener;
use tokio::runtime::Builder;
use tokio::signal::unix::SignalKind;

use crate::config::Config;
use crate::config::DomainName;
use crate::config::HttpsUpgradeMode;
use crate::database::Database;
use crate::database_task::DatabaseCommand;
use crate::database_task::DbCmdDelivery;
use crate::database_task::DbCmdDownload;
use crate::database_task::DbCmdOrigin;
use crate::database_task::db_loop;
use crate::deb_mirror::Mirror;
use crate::deb_mirror::Origin;
use crate::deb_mirror::ResourceFile;
use crate::deb_mirror::parse_request_path;
use crate::deb_mirror::valid_architecture;
use crate::deb_mirror::valid_component;
use crate::deb_mirror::valid_distribution;
use crate::deb_mirror::valid_filename;
use crate::deb_mirror::valid_mirrorname;
use crate::error::ErrorReport;
use crate::error::MirrorDownloadRate;
use crate::error::ProxyCacheError;
use crate::guards::DownloadBarrier;
use crate::guards::InitBarrier;
use crate::http_etag::if_none_match;
use crate::http_etag::is_valid_etag;
use crate::http_etag::read_etag;
use crate::http_etag::write_etag;
use crate::http_range::format_http_date;
use crate::http_range::http_datetime_to_systemtime;
use crate::http_range::systemtime_to_http_datetime;
use crate::humanfmt::HumanFmt;
use crate::logstore::LogStore;
use crate::ringbuffer::RingBuffer;
use crate::task_cache_scan::task_cache_scan;
use crate::task_cleanup::task_cleanup;
use crate::task_setup::task_setup;
use crate::utils::TempPath;
use crate::utils::tokio_tempfile;
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

type HttpClient = hyper_util::client::legacy::Client<
    hyper_timeout::TimeoutConnector<HttpsConnector<HttpConnector>>,
    Empty<bytes::Bytes>,
>;

pub(crate) const APP_NAME: &str = env!("CARGO_PKG_NAME");
const APP_VERSION: &str = env!("CARGO_PKG_VERSION");
const APP_USER_AGENT: &str = concat!(env!("CARGO_PKG_NAME"), "/", env!("CARGO_PKG_VERSION"),);

pub(crate) const APP_VIA: &str = concat!("1.1 ", env!("CARGO_PKG_NAME"));

const RETENTION_TIME: Duration = Duration::from_hours(8 * 7 * 24); /* 8 weeks */

const VOLATILE_UNKNOWN_CONTENT_LENGTH_UPPER: NonZero<u64> = nonzero!(1024 * 1024); /* 1MiB */

#[derive(Copy, Clone, Debug)]
pub(crate) struct ClientInfo {
    addr: SocketAddr,
}

impl ClientInfo {
    #[must_use]
    pub(crate) fn new(addr: SocketAddr) -> Self {
        Self { addr }
    }

    #[must_use]
    #[inline]
    pub(crate) fn ip(&self) -> IpAddr {
        self.addr.ip().to_canonical()
    }
}

impl Display for ClientInfo {
    #[inline]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.ip())
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum Scheme {
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
struct SchemeKey {
    host: String,
    port: Option<u16>,
}

#[derive(Hash)]
struct SchemeKeyRef<'a> {
    host: &'a str,
    port: Option<u16>,
}

impl Equivalent<SchemeKey> for SchemeKeyRef<'_> {
    fn equivalent(&self, key: &SchemeKey) -> bool {
        self.host == key.host && self.port == key.port
    }
}

#[expect(
    clippy::from_over_into,
    reason = "Into is used via entry_ref() and From is not needed"
)]
impl Into<SchemeKey> for &SchemeKeyRef<'_> {
    fn into(self) -> SchemeKey {
        SchemeKey {
            host: self.host.to_owned(),
            port: self.port,
        }
    }
}

static SCHEME_CACHE: OnceLock<parking_lot::RwLock<HashMap<SchemeKey, Scheme>>> = OnceLock::new();

pub(crate) async fn request_with_retry(
    client: &HttpClient,
    request: Request<Empty<bytes::Bytes>>,
) -> Result<Response<Incoming>, hyper_util::client::legacy::Error> {
    const MAX_ATTEMPTS: u32 = 10;

    debug_assert_eq!(
        request.body().size_hint().exact(),
        Some(0),
        "Invariant of Empty"
    );

    let (mut parts, _body) = request.into_parts();

    let https_upgrade_mode = global_config().https_upgrade_mode;

    let orig_scheme = parts.uri.scheme().cloned();

    let cached_scheme = parts.uri.authority().and_then(|auth| {
        let key = SchemeKeyRef {
            host: auth.host(),
            port: auth.port_u16(),
        };
        SCHEME_CACHE
            .get()
            .expect("Initialized in main()")
            .read()
            .get(&key)
            .copied()
    });

    let mut https_upgrade_test = false;

    if let Some(os) = &orig_scheme
        && *os != http::uri::Scheme::HTTP
    {
        debug!("Not altering {os} scheme for request {}", parts.uri);
    } else if let Some(scheme) = cached_scheme {
        debug!(
            "Using cached scheme {scheme} for host {}, original scheme is {orig_scheme:?}",
            parts
                .uri
                .authority()
                .expect("authority must exist for a cache entry")
        );

        let mut uri_parts = parts.uri.into_parts();
        uri_parts.scheme = Some(scheme.into());
        parts.uri = Uri::from_parts(uri_parts).expect("valid parts");
    } else if let Some(auth) = parts.uri.authority() {
        if global_config()
            .http_only_mirrors
            .iter()
            .any(|mirror| mirror.permits(auth.host()))
        {
            debug!("Not altering {orig_scheme:?} scheme for http-only host {auth}");
        } else if https_upgrade_mode != HttpsUpgradeMode::Never {
            debug!(
                "No cached scheme for host {auth}, trying https upgrade from original scheme {orig_scheme:?}..."
            );

            // try https upgrade
            let mut uri_parts = parts.uri.into_parts();
            uri_parts.scheme = Some(http::uri::Scheme::HTTPS);
            parts.uri = Uri::from_parts(uri_parts).expect("valid parts");
            https_upgrade_test = true;
        }
    }

    #[expect(
        clippy::items_after_statements,
        reason = "keep definition before grouped call sites"
    )]
    async fn inner_loop(
        client: &HttpClient,
        mut parts: http::request::Parts,
        orig_scheme: Option<http::uri::Scheme>,
        cached_scheme: Option<Scheme>,
        https_upgrade_mode: HttpsUpgradeMode,
        mut https_upgrade_test: bool,
    ) -> Result<Response<Incoming>, (hyper_util::client::legacy::Error, Uri)> {
        let mut attempt = 1;
        let mut sleep_prev = 0;
        let mut sleep_curr = 500;

        loop {
            let req_clone = Request::from_parts(parts.clone(), Empty::new());

            let _: Never = match client.request(req_clone).await {
                Ok(response) => {
                    if cached_scheme.is_none()
                        && let Some(auth) = parts.uri.authority()
                    {
                        let scheme = match parts.uri.scheme() {
                            Some(s) if *s == http::uri::Scheme::HTTP => Some(Scheme::Http),
                            Some(s) if *s == http::uri::Scheme::HTTPS => Some(Scheme::Https),
                            s => {
                                debug!("Not caching unsupported scheme {s:?} for host {auth}");
                                None
                            }
                        };
                        if let Some(scheme) = scheme {
                            let key = SchemeKeyRef {
                                host: auth.host(),
                                port: auth.port_u16(),
                            };
                            let scheme_cache = SCHEME_CACHE.get().expect("Initialized in main()");
                            if !scheme_cache.read().contains_key(&key)
                                && let EntryRef::Vacant(ventry) =
                                    scheme_cache.write().entry_ref(&key)
                            {
                                ventry.insert(scheme);
                                debug!(
                                    "Added cached {scheme} scheme for host {auth}, original scheme was {orig_scheme:?}"
                                );
                            }
                        }
                    }
                    return Ok(response);
                }
                Err(err) if !err.is_connect() => {
                    warn_once_or_info!(
                        "Request of internal client to {} failed:  {}",
                        parts.uri,
                        ErrorReport::new(&err)
                    );
                    return Err((err, parts.uri));
                }
                Err(err) => {
                    if attempt > 2
                        && https_upgrade_test
                        && https_upgrade_mode != HttpsUpgradeMode::Always
                    {
                        assert_eq!(
                            cached_scheme, None,
                            "https upgrade is only tried when no cached scheme exists"
                        );
                        assert_eq!(
                            https_upgrade_mode,
                            HttpsUpgradeMode::Auto,
                            "branch ensures value is not Always, and Never does not perform upgrades"
                        );

                        debug!(
                            "Https upgrade failed for host {} after {attempt} connection attempts, re-trying with original scheme {orig_scheme:?}...",
                            parts
                                .uri
                                .authority()
                                .expect("authority must exist for a https upgrade")
                        );

                        // reset https upgrade
                        let mut uri_parts = parts.uri.into_parts();
                        uri_parts.scheme.clone_from(&orig_scheme);
                        parts.uri = Uri::from_parts(uri_parts).expect("valid parts");
                        https_upgrade_test = false;
                        sleep_prev = 0;
                        sleep_curr = 500;
                        continue;
                    }

                    if attempt > MAX_ATTEMPTS {
                        if let Some(auth) = parts.uri.authority() {
                            let key = SchemeKeyRef {
                                host: auth.host(),
                                port: auth.port_u16(),
                            };

                            let value = SCHEME_CACHE
                                .get()
                                .expect("Initialized in main()")
                                .write()
                                .remove(&key);
                            if let Some(scheme) = value {
                                debug!(
                                    "Removed cached scheme {scheme} for host {auth} after {attempt} connection attempts, original scheme was {orig_scheme:?}"
                                );
                            }
                        }

                        return Err((err, parts.uri));
                    }

                    debug!(
                        "Failed to connect to {} after {attempt} connection attempts, will retry in {sleep_curr} ms:  {}",
                        parts.uri,
                        ErrorReport::new(&err)
                    );

                    attempt += 1;

                    tokio::time::sleep(Duration::from_millis(sleep_curr)).await;
                    (sleep_curr, sleep_prev) = (sleep_curr + sleep_prev, sleep_curr);

                    continue;
                }
            };
        }
    }

    if https_upgrade_test {
        assert_eq!(
            cached_scheme, None,
            "https upgrade is only tried when no cached scheme exists"
        );

        let client = client.clone();

        // Spawn a new task such that even if the client disconnects,
        // the task will continue to run and initialize the scheme cache.
        tokio::task::spawn(async move {
            let result =
                inner_loop(&client, parts, orig_scheme, None, https_upgrade_mode, true).await;
            if let Err(ref err) = result {
                warn!(
                    "Failed to initialize scheme cache for host {} in background task:  {}",
                    err.1
                        .authority()
                        .expect("authority exists in case of https upgrade test"),
                    ErrorReport::new(&err.0)
                );
            }
            result.map_err(|err| err.0)
        })
        .await
        .expect("task should not panic")
    } else {
        inner_loop(
            client,
            parts,
            orig_scheme,
            cached_scheme,
            https_upgrade_mode,
            false,
        )
        .await
        .map_err(|err| err.0)
    }
}

#[must_use]
fn quick_response<T: Into<bytes::Bytes>>(
    status: hyper::StatusCode,
    message: T,
) -> Response<ProxyCacheBody> {
    Response::builder()
        .status(status)
        .header(SERVER, APP_NAME)
        .header(DATE, format_http_date())
        .header(CONNECTION, "keep-alive")
        .header(CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(ProxyCacheBody::Full(Full::new(message.into())))
        .expect("Response is valid")
}

/* Adopted from http_body_util::StreamBody */
#[pin_project(PinnedDrop)]
struct DeliveryStreamBody<S> {
    #[pin]
    stream: S,
    start: Instant,
    size: u64,
    partial: bool,
    transferred_bytes: u64,
    database_tx: Option<tokio::sync::mpsc::Sender<DatabaseCommand>>,
    conn_details: Option<ConnectionDetails>,
    error: Option<String>,
    _counter: client_counter::ClientDownload,
}

impl<S> DeliveryStreamBody<S> {
    #[must_use]
    fn new(
        stream: S,
        size: u64,
        partial: bool,
        database_tx: tokio::sync::mpsc::Sender<DatabaseCommand>,
        conn_details: ConnectionDetails,
    ) -> Self {
        Self {
            stream,
            start: Instant::now(),
            size,
            partial,
            transferred_bytes: 0,
            database_tx: Some(database_tx),
            conn_details: Some(conn_details),
            error: None,
            _counter: client_counter::ClientDownload::new(),
        }
    }
}

impl<S, D, E: ToString> Body for DeliveryStreamBody<S>
where
    S: futures_util::Stream<Item = Result<Frame<D>, E>>,
    D: bytes::Buf,
{
    type Data = D;
    type Error = E;

    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        match self.as_mut().project().stream.poll_next(cx) {
            Ready(Some(result)) => {
                match &result {
                    Ok(frame) => {
                        if let Some(data) = frame.data_ref() {
                            *self.project().transferred_bytes += data.remaining() as u64;
                        }
                    }
                    Err(err) => *self.project().error = Some(err.to_string()),
                }
                Ready(Some(result))
            }
            Pending => Pending,
            Ready(None) => Ready(None),
        }
    }

    fn size_hint(&self) -> SizeHint {
        match self.size.checked_sub(self.transferred_bytes) {
            Some(val) => SizeHint::with_exact(val),
            None => SizeHint::default(),
        }
    }
}

#[pinned_drop]
impl<S> PinnedDrop for DeliveryStreamBody<S> {
    fn drop(self: std::pin::Pin<&mut Self>) {
        let size = self.size;
        let partial = self.partial;
        let duration = self.start.elapsed();
        let transferred_bytes = self.transferred_bytes;
        let project = self.project();
        let db_tx = project.database_tx.take().expect("Option is set in new()");
        let cd = project.conn_details.take().expect("Option is set in new()");
        let error = project.error.take();
        tokio::task::spawn(async move {
            let aliased = match cd.aliased_host {
                Some(alias) => format!(" aliased to host {alias}"),
                None => String::new(),
            };
            if transferred_bytes == size {
                info!(
                    "Served cached file {} from mirror {}{} for client {} in {} via stream (size={}, rate={})",
                    cd.debname,
                    cd.mirror,
                    aliased,
                    cd.client,
                    HumanFmt::Time(duration.into()),
                    HumanFmt::Size(size),
                    HumanFmt::Rate(size, duration)
                );

                let cmd = DatabaseCommand::Delivery(DbCmdDelivery {
                    mirror: cd.mirror,
                    debname: cd.debname,
                    size,
                    elapsed: duration,
                    partial,
                    client_ip: cd.client.ip(),
                });
                db_tx.send(cmd).await.expect("database task should not die");
            } else if transferred_bytes == 0 && duration < coarsetime::Duration::from_secs(1) {
                info!(
                    "Aborted serving cached file {} from mirror {}{} for client {} after {} via stream:  {}",
                    cd.debname,
                    cd.mirror,
                    aliased,
                    cd.client,
                    HumanFmt::Time(duration.into()),
                    error.unwrap_or_else(|| String::from("unknown reason")),
                );
            } else {
                warn!(
                    "Failed to serve cached file {} from mirror {}{} for client {} after {} via stream (size={}, transferred={}, rate={}):  {}",
                    cd.debname,
                    cd.mirror,
                    aliased,
                    cd.client,
                    HumanFmt::Time(duration.into()),
                    HumanFmt::Size(size),
                    HumanFmt::Size(transferred_bytes),
                    HumanFmt::Rate(transferred_bytes, duration),
                    error.unwrap_or_else(|| String::from("unknown reason")),
                );
            }
        });
    }
}

#[pin_project(project = EnumProj)]
enum ProxyCacheBody {
    #[cfg(feature = "mmap")]
    Mmap(#[pin] MmapBody),
    #[cfg(feature = "mmap")]
    MmapRateChecked(#[pin] RateCheckedBody<MmapBody>, IpAddr),
    Boxed(#[pin] BoxBody<bytes::Bytes, Box<ProxyCacheError>>),
    Full(#[pin] Full<bytes::Bytes>),
    Empty(#[pin] Empty<bytes::Bytes>),
}

impl Debug for ProxyCacheBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            #[cfg(feature = "mmap")]
            Self::Mmap(_) => f.debug_tuple("Mmap").finish(),
            #[cfg(feature = "mmap")]
            Self::MmapRateChecked(_, _) => f.debug_tuple("MmapRateChecked").finish(),
            Self::Boxed(_) => f.debug_tuple("Boxed").finish(),
            Self::Full(_) => f.debug_tuple("Full").finish(),
            Self::Empty(_) => f.debug_tuple("Empty").finish(),
        }
    }
}

impl Body for ProxyCacheBody {
    type Data = ProxyCacheBodyData;

    type Error = Box<ProxyCacheError>;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        match self.project() {
            #[cfg(feature = "mmap")]
            EnumProj::Mmap(memory_map) => memory_map
                .poll_frame(cx)
                .map_ok(|frame| frame.map_data(ProxyCacheBodyData::Mmap))
                .map_err(|never| match never {}),

            #[cfg(feature = "mmap")]
            EnumProj::MmapRateChecked(memory_map, client_ip) => memory_map
                .poll_frame(cx)
                .map_ok(|frame| frame.map_data(ProxyCacheBodyData::Mmap))
                .map_err(|rerr| match *rerr {
                    RateCheckedBodyErr::RateTimeout(error) => {
                        Box::new(ProxyCacheError::ClientDownloadRate {
                            error,
                            client_ip: *client_ip,
                        })
                    }
                    RateCheckedBodyErr::Inner(never) => match never {},
                }),

            EnumProj::Boxed(bytes) => bytes
                .poll_frame(cx)
                .map_ok(|frame| frame.map_data(ProxyCacheBodyData::Bytes)),

            EnumProj::Full(bytes) => bytes
                .poll_frame(cx)
                .map_ok(|frame| frame.map_data(ProxyCacheBodyData::Bytes))
                .map_err(|never| match never {}),

            EnumProj::Empty(bytes) => bytes
                .poll_frame(cx)
                .map_ok(|frame| frame.map_data(ProxyCacheBodyData::Bytes))
                .map_err(|never| match never {}),
        }
    }

    fn size_hint(&self) -> SizeHint {
        match self {
            #[cfg(feature = "mmap")]
            Self::Mmap(mmap_body) => mmap_body.size_hint(),
            #[cfg(feature = "mmap")]
            Self::MmapRateChecked(rate_checked_body, _ip_addr) => rate_checked_body.size_hint(),
            Self::Boxed(box_body) => box_body.size_hint(),
            Self::Full(full_body) => full_body.size_hint(),
            Self::Empty(empty_body) => empty_body.size_hint(),
        }
    }

    fn is_end_stream(&self) -> bool {
        match self {
            #[cfg(feature = "mmap")]
            Self::Mmap(mmap_body) => mmap_body.is_end_stream(),
            #[cfg(feature = "mmap")]
            Self::MmapRateChecked(rate_checked_body, _ip_addr) => rate_checked_body.is_end_stream(),
            Self::Boxed(box_body) => box_body.is_end_stream(),
            Self::Full(full_body) => full_body.is_end_stream(),
            Self::Empty(empty_body) => empty_body.is_end_stream(),
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

#[cfg(feature = "mmap")]
const MMAP_FRAME_SIZE: usize = 2 * 1024 * 1024; // 2MiB

#[cfg(feature = "mmap")]
struct MmapBody {
    mapping: Arc<Mmap>,
    position: usize,
    length: usize,
    partial: bool,
    start: Instant,
    database_tx: Option<tokio::sync::mpsc::Sender<DatabaseCommand>>,
    conn_details: Option<ConnectionDetails>,
    _counter: client_counter::ClientDownload,
}

#[cfg(feature = "mmap")]
impl MmapBody {
    #[must_use]
    fn new(
        mapping: Mmap,
        length: usize,
        partial: bool,
        database_tx: tokio::sync::mpsc::Sender<DatabaseCommand>,
        conn_details: ConnectionDetails,
    ) -> Self {
        Self {
            mapping: Arc::new(mapping),
            position: 0,
            length,
            partial,
            start: Instant::now(),
            database_tx: Some(database_tx),
            conn_details: Some(conn_details),
            _counter: client_counter::ClientDownload::new(),
        }
    }
}

#[cfg(feature = "mmap")]
impl Drop for MmapBody {
    fn drop(&mut self) {
        let size = self.length as u64;
        let partial = self.partial;
        let elapsed = self.start.elapsed();
        let transferred_bytes = self.position as u64;
        let db_tx = self.database_tx.take().expect("set in new()");
        let cd = self.conn_details.take().expect("set in new()");
        tokio::task::spawn(async move {
            let aliased = match cd.aliased_host {
                Some(alias) => format!(" aliased to host {alias}"),
                None => String::new(),
            };
            if transferred_bytes == size {
                info!(
                    "Served cached file {} from mirror {}{} for client {} in {} via mmap (size={}, rate={})",
                    cd.debname,
                    cd.mirror,
                    aliased,
                    cd.client,
                    HumanFmt::Time(elapsed.into()),
                    HumanFmt::Size(size),
                    HumanFmt::Rate(size, elapsed)
                );

                let cmd = DatabaseCommand::Delivery(DbCmdDelivery {
                    mirror: cd.mirror,
                    debname: cd.debname,
                    size,
                    elapsed,
                    partial,
                    client_ip: cd.client.ip(),
                });
                db_tx.send(cmd).await.expect("database task should not die");
            } else if transferred_bytes == 0 {
                info!(
                    "Aborted serving cached file {} from mirror {}{} for client {} after {} via mmap",
                    cd.debname,
                    cd.mirror,
                    aliased,
                    cd.client,
                    HumanFmt::Time(elapsed.into()),
                );
            } else {
                warn!(
                    "Failed to serve cached file {} from mirror {}{} for client {} after {} via mmap (size={}, transferred={}, rate={})",
                    cd.debname,
                    cd.mirror,
                    aliased,
                    cd.client,
                    HumanFmt::Time(elapsed.into()),
                    HumanFmt::Size(size),
                    HumanFmt::Size(transferred_bytes),
                    HumanFmt::Rate(transferred_bytes, elapsed),
                );
            }
        });
    }
}

#[cfg(feature = "mmap")]
struct MmapData {
    mapping: Arc<Mmap>,
    position: usize,
    remaining: usize,
}

#[cfg(feature = "mmap")]
impl bytes::buf::Buf for MmapData {
    fn remaining(&self) -> usize {
        self.remaining
    }

    fn chunk(&self) -> &[u8] {
        &self.mapping[self.position..(self.position + self.remaining)]
    }

    fn advance(&mut self, cnt: usize) {
        assert!(cnt <= self.remaining, "suggested by trait");
        self.position += cnt;
        self.remaining -= cnt;
    }
}

#[cfg(feature = "mmap")]
impl Body for MmapBody {
    type Data = MmapData;
    type Error = Infallible;

    fn is_end_stream(&self) -> bool {
        debug_assert!(
            self.position <= self.length,
            "position must not exceed length"
        );
        self.position == self.length
    }

    fn size_hint(&self) -> SizeHint {
        debug_assert!(
            self.position <= self.length,
            "position must not exceed length"
        );
        SizeHint::with_exact((self.length - self.position) as u64)
    }

    fn poll_frame(
        mut self: Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        // same logic as in Self::is_end_stream()
        debug_assert!(
            self.position <= self.length,
            "position must not exceed length"
        );
        let remaining_total = self.length - self.position;
        if remaining_total == 0 {
            return Ready(None);
        }

        let chunk_size = remaining_total.min(MMAP_FRAME_SIZE);

        let frame = Frame::data(MmapData {
            mapping: Arc::clone(&self.mapping),
            position: self.position,
            remaining: chunk_size,
        });

        self.as_mut().position += chunk_size;

        Ready(Some(Ok(frame)))
    }
}

enum EtagState {
    Some(String),
    Failure,
    Unknown,
}

impl EtagState {
    fn from_option(etag: Option<String>) -> Self {
        match etag {
            Some(etag) => Self::Some(etag),
            None => Self::Failure,
        }
    }
}

#[must_use]
async fn serve_cached_file(
    conn_details: ConnectionDetails,
    req: &Request<Empty<()>>,
    database_tx: tokio::sync::mpsc::Sender<DatabaseCommand>,
    file: tokio::fs::File,
    file_path: &Path,
    file_etag: EtagState,
) -> Response<ProxyCacheBody> {
    fn decide_serve_304(
        req: &Request<Empty<()>>,
        file_etag: Option<&str>,
        local_modification_time: SystemTime,
        conn_details: &ConnectionDetails,
    ) -> bool {
        // Handle If-None-Match (takes precedence over If-Modified-Since per RFC 9110 §13.1.2)
        if let Some(inm) = req.headers().get(IF_NONE_MATCH) {
            // If we don't have a local ETag or the header is invalid, conservatively serve the body.
            let Some(etag) = file_etag else {
                return false;
            };

            let Ok(inm_str) = inm.to_str() else {
                warn_once!(
                    "Client {} sent an invalid If-None-Match header: {inm:?}",
                    conn_details.client
                );
                return false;
            };

            return if_none_match(inm_str, etag);
        }

        if let Some(ims) = req.headers().get(IF_MODIFIED_SINCE)
            && let Some(ims_str) = ims.to_str().ok()
            && let Some(ims_time) = http_datetime_to_systemtime(ims_str)
            && local_modification_time <= ims_time
        {
            return true;
        }

        false
    }

    let aliased = match conn_details.aliased_host {
        Some(alias) => format!(" aliased to host {alias}"),
        None => String::new(),
    };

    let metadata = match file.metadata().await {
        Ok(m) => m,
        Err(err) => {
            error!(
                "Failed to get metadata of cached file `{}`:  {err}",
                file_path.display()
            );
            return quick_response(StatusCode::INTERNAL_SERVER_ERROR, "Cache Access Failure");
        }
    };

    let file_size = metadata.len();

    // Use the provided ETag or fall back to reading from the file if not provided
    let file_etag = match file_etag {
        EtagState::Some(etag) => Some(etag),
        EtagState::Failure => None,
        EtagState::Unknown => read_etag(&file, file_path),
    };

    // Cache entries are replaced on update, not overridden, so the creation time is the time the file was last modified.
    // The modified file timestamp is used to store the last up-to-date check against the upstream mirror, if creation timestamps are supported.
    let last_modified = metadata.created().unwrap_or_else(|_err| {
        metadata
            .modified()
            .expect("Platform should support modification timestamps via setup check")
    });

    // Handle If-None-Match and If-Modified-Since
    let serve_304 = decide_serve_304(req, file_etag.as_deref(), last_modified, &conn_details);

    if serve_304 {
        info!(
            "Serving 304 Not Modified for cached file {} from mirror {}{} for client {} via hyper",
            conn_details.debname, conn_details.mirror, aliased, conn_details.client
        );

        let mut builder = Response::builder()
            .status(StatusCode::NOT_MODIFIED)
            .header(DATE, format_http_date())
            .header(VIA, APP_VIA)
            .header(CONNECTION, "keep-alive")
            .header(
                LAST_MODIFIED,
                HeaderValue::try_from(systemtime_to_http_datetime(last_modified))
                    .expect("HTTP date is valid"),
            )
            .header(
                AGE,
                HeaderValue::from(last_modified.elapsed().map_or(0, |dur| dur.as_secs())),
            );
        if let Some(ref etag) = file_etag {
            builder = builder.header(
                ETAG,
                HeaderValue::try_from(etag.as_str()).expect("ETag is validated by read_etag"),
            );
        }
        let response = builder
            .body(ProxyCacheBody::Empty(Empty::new()))
            .expect("HTTP response is valid");

        trace!("Outgoing response: {response:?}");

        return response;
    }

    let (http_status, content_start, content_length, content_range, partial) = if let Some(range) =
        req.headers().get(RANGE).and_then(|val| val.to_str().ok())
        && let Some((content_range, start, content_length)) = http_parse_range(
            range,
            req.headers()
                .get(IF_RANGE)
                .and_then(|val| val.to_str().ok()),
            file_size,
            last_modified,
            file_etag.as_deref(),
        ) {
        (
            StatusCode::PARTIAL_CONTENT,
            start,
            content_length,
            Some(content_range),
            true,
        )
    } else {
        (StatusCode::OK, 0, file_size, None, false)
    };

    #[cfg(feature = "mmap")]
    if content_length >= global_config().mmap_threshold.get() {
        let mmap_content_length: usize = match content_length.try_into() {
            Ok(c) => c,
            Err(_err @ std::num::TryFromIntError { .. }) => {
                error!(
                    "Content length of {} for file `{}` from mirror {}{} for client {} is too large",
                    content_length,
                    file_path.display(),
                    conn_details.mirror,
                    aliased,
                    conn_details.client
                );
                return quick_response(StatusCode::INTERNAL_SERVER_ERROR, "Cache Access Failure");
            }
        };

        info!(
            "Serving cached file {} from mirror {}{} for client {} via mmap...",
            conn_details.debname, conn_details.mirror, aliased, conn_details.client
        );

        return serve_cached_file_mmap(
            conn_details,
            database_tx,
            file,
            file_path,
            last_modified,
            http_status,
            mmap_content_length,
            content_start,
            content_range,
            partial,
            file_etag.as_deref(),
        )
        .await;
    }

    info!(
        "Serving cached file {} from mirror {}{} for client {} via stream...",
        conn_details.debname, conn_details.mirror, aliased, conn_details.client
    );

    serve_cached_file_buf(
        conn_details,
        database_tx,
        file,
        file_path,
        file_size,
        last_modified,
        http_status,
        content_length,
        content_start,
        content_range,
        partial,
        file_etag.as_deref(),
    )
    .await
}

#[cfg(feature = "mmap")]
#[expect(clippy::too_many_arguments, reason = "function has only 1 caller")]
#[inline]
async fn serve_cached_file_mmap(
    conn_details: ConnectionDetails,
    database_tx: tokio::sync::mpsc::Sender<DatabaseCommand>,
    file: tokio::fs::File,
    file_path: &Path,
    last_modified: SystemTime,
    http_status: StatusCode,
    content_length: usize,
    content_start: u64,
    content_range: Option<String>,
    partial: bool,
    etag: Option<&str>,
) -> Response<ProxyCacheBody> {
    let file_pathbuf = file_path.to_path_buf();
    let client_ip = conn_details.client.ip();

    trace!(
        "Using mmap(2) with start={content_start} and length={content_length} from content_range={content_range:?} for file `{}`",
        file_pathbuf.display()
    );

    let Some(memory_map) = tokio::task::spawn_blocking(move || {
        // SAFETY:
        // The file is only read from and only forwarded as bytes to a network socket.
        // Also clients perform a signature check on received packages.
        let memory_map = unsafe {
            MmapOptions::new()
                .offset(content_start)
                .len(content_length)
                .map(&file)
        }
        .inspect_err(|err| {
            error!(
                "Failed to mmap downloaded file `{}`:  {err}",
                file_pathbuf.display()
            );
        })
        .ok()?;

        debug_assert_eq!(
            memory_map.len(),
            content_length,
            "actual mmap length must match requested length"
        );

        // close file, since mapping is independent
        drop(file);

        if let Err(err) = memory_map.advise(Advice::Sequential) {
            warn_once_or_info!(
                "Failed to advice memory mapping of file `{}`:  {err}",
                file_pathbuf.display()
            );
        }

        Some(memory_map)
    })
    .await
    .expect("task should not panic") else {
        return quick_response(StatusCode::INTERNAL_SERVER_ERROR, "Cache Access Failure");
    };

    let memory_body = MmapBody::new(
        memory_map,
        content_length,
        partial,
        database_tx,
        conn_details,
    );

    let config = global_config();

    let body = match config.min_download_rate {
        Some(rate) => ProxyCacheBody::MmapRateChecked(
            RateCheckedBody::new(memory_body, rate, config.rate_check_timeframe),
            client_ip,
        ),
        None => ProxyCacheBody::Mmap(memory_body),
    };

    serve_cached_file_response(
        http_status,
        last_modified,
        content_length as u64,
        body,
        content_range,
        etag,
    )
}

#[expect(clippy::too_many_arguments, reason = "function has only 1 caller")]
#[inline]
async fn serve_cached_file_buf(
    conn_details: ConnectionDetails,
    database_tx: tokio::sync::mpsc::Sender<DatabaseCommand>,
    mut file: tokio::fs::File,
    file_path: &Path,
    file_size: u64,
    last_modified: SystemTime,
    http_status: StatusCode,
    content_length: u64,
    start: u64,
    content_range: Option<String>,
    partial: bool,
    etag: Option<&str>,
) -> Response<ProxyCacheBody> {
    if let Err(err) = file.seek(std::io::SeekFrom::Start(start)).await {
        error!(
            "Error seeking cached file `{}` to {start}/{file_size}:  {err}",
            file_path.display()
        );
        return quick_response(StatusCode::INTERNAL_SERVER_ERROR, "Cache Access Failure");
    }

    let reader_stream =
        tokio_util::io::ReaderStream::with_capacity(file, global_config().buffer_size);
    let delivery_body = DeliveryStreamBody::new(
        reader_stream.map_ok(Frame::data),
        content_length,
        partial,
        database_tx,
        conn_details,
    );
    let body = ProxyCacheBody::Boxed(
        delivery_body
            .map_err(|err| Box::new(ProxyCacheError::Io(err)))
            .boxed(),
    );

    serve_cached_file_response(
        http_status,
        last_modified,
        content_length,
        body,
        content_range,
        etag,
    )
}

fn serve_cached_file_response(
    http_status: StatusCode,
    last_modified: SystemTime,
    content_length: u64,
    body: ProxyCacheBody,
    content_range: Option<String>,
    etag: Option<&str>,
) -> Response<ProxyCacheBody> {
    /*
     * Original headers:
     *
     *  "connection":             "keep-alive",
     *  "content-length":         "62092296",
     *  "server":                 "Apache",
     *  "x-content-type-options": "nosniff",
     *  "x-frame-options":        "sameorigin",
     *  "referrer-policy":        "no-referrer",
     *  "x-xss-protection":       "1",
     *  "permissions-policy":     "interest-cohort=()",
     *  "last-modified":          "Wed, 20 Dec 2023 04:45:32 GMT",
     *  "etag":                   "\"3b37408-60ce9a73589f2\"",
     *  "x-clacks-overhead":      "GNU Terry Pratchett",
     *  "cache-control":          "public, max-age=2592000",
     *  "content-type":           "application/vnd.debian.binary-package",
     *  "via":                    "1.1 varnish, 1.1 varnish",
     *  "accept-ranges":          "bytes",
     *  "age":                    "1544533",
     *  "date":                   "Sat, 20 Jan 2024 20:28:06 GMT",
     *  "x-served-by":            "cache-ams21052-AMS, cache-fra-eddf8230062-FRA",
     *  "x-cache":                "HIT, HIT", "x-cache-hits": "1, 0",
     *  "x-timer":                "S1705782486.334221,VS0,VE1"
     */

    let mut response = Response::builder()
        .status(http_status)
        .header(DATE, format_http_date())
        .header(VIA, APP_VIA)
        .header(CONNECTION, "keep-alive")
        .header(CONTENT_LENGTH, HeaderValue::from(content_length))
        .header(CONTENT_TYPE, "application/vnd.debian.binary-package")
        .header(
            LAST_MODIFIED,
            HeaderValue::try_from(systemtime_to_http_datetime(last_modified))
                .expect("date string is valid"),
        )
        .header(ACCEPT_RANGES, "bytes")
        .header(
            AGE,
            HeaderValue::from(last_modified.elapsed().map_or(0, |dur| dur.as_secs())),
        )
        .body(body)
        .expect("HTTP response is valid");

    if let Some(ct) = content_range {
        let r = response.headers_mut().append(
            CONTENT_RANGE,
            ct.try_into().expect("content range string is valid"),
        );
        assert!(!r, "header does not exist by previous construction");
    }

    if let Some(etag) = etag {
        let r = response.headers_mut().append(
            ETAG,
            HeaderValue::try_from(etag).expect("ETag is validated by read_etag"),
        );
        assert!(!r, "header does not exist by previous construction");
    }

    trace!("Outgoing response of cached file: {response:?}");

    response
}

#[derive(Clone)]
pub(crate) struct AppState {
    pub(crate) database: Database,
    pub(crate) database_tx: tokio::sync::mpsc::Sender<DatabaseCommand>,
    pub(crate) https_client: HttpClient,
    pub(crate) active_downloads: ActiveDownloads,
}

#[must_use]
async fn serve_volatile_file(
    conn_details: ConnectionDetails,
    req: Request<Empty<()>>,
    file: tokio::fs::File,
    file_path: &Path,
    appstate: AppState,
) -> Response<ProxyCacheBody> {
    debug_assert_eq!(
        conn_details.cached_flavor,
        CachedFlavor::Volatile,
        "serve_volatile_file() assumes volatile flavor"
    );

    let (local_creation_time, local_modification_time) = match file.metadata().await {
        Ok(data) => (
            data.created().ok(),
            data.modified()
                .expect("Platform should support modification timestamps via setup check"),
        ),
        Err(err) => {
            error!(
                "Failed to get metadata of file `{}`:  {err}",
                file_path.display()
            );
            return quick_response(StatusCode::INTERNAL_SERVER_ERROR, "Cache Access Failure");
        }
    };

    // Cache volatile files for short periods to reduce up-to-date requests
    if let Ok(elapsed) = local_modification_time.elapsed()
        && elapsed < Duration::from_secs(30)
    {
        debug!(
            "Volatile file `{}` is just {} old (limit: 30s), serving cached version...",
            file_path.display(),
            HumanFmt::Time(elapsed)
        );

        return serve_cached_file(
            conn_details,
            &req,
            appstate.database_tx,
            file,
            file_path,
            EtagState::Unknown,
        )
        .await;
    }

    let (init_tx, status) = appstate
        .active_downloads
        .insert(&conn_details.mirror, &conn_details.debname);

    let Some(init_tx) = init_tx else {
        debug!(
            "Serving file {} already in cache / download from mirror {} for client {}...",
            conn_details.debname, conn_details.mirror, conn_details.client
        );
        return serve_downloading_file(
            conn_details,
            req,
            appstate.database_tx,
            status,
            EtagState::Unknown,
        )
        .await;
    };

    serve_new_file(
        conn_details,
        status,
        init_tx,
        req,
        CacheFileStat::Volatile {
            file,
            file_path,
            local_creation_time,
            local_modification_time,
        },
        appstate,
    )
    .await
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) enum CachedFlavor {
    Permanent,
    Volatile,
}

#[derive(Clone, Debug)]
pub(crate) struct ConnectionDetails {
    pub(crate) client: ClientInfo,
    pub(crate) mirror: Mirror,
    pub(crate) aliased_host: Option<&'static DomainName>,
    pub(crate) debname: String,
    pub(crate) cached_flavor: CachedFlavor,
    pub(crate) subdir: Option<&'static Path>,
}

impl ConnectionDetails {
    #[must_use]
    pub(crate) fn cache_dir_path(&self) -> PathBuf {
        let root = &global_config().cache_directory;

        let host = self.aliased_host.unwrap_or(&self.mirror.host);
        let host = host.format_cache_dir(self.mirror.port);
        let host = Path::new(host.as_ref());
        assert!(
            host.is_relative(),
            "path construction must not contain absolute components"
        );

        let uri_path = Path::new(&self.mirror.path);
        assert!(
            uri_path.is_relative(),
            "path construction must not contain absolute components"
        );

        let subdir = self.subdir.unwrap_or_else(|| Path::new(""));
        assert!(
            subdir.is_relative(),
            "path construction must not contain absolute components"
        );

        [root.as_path(), host, uri_path, subdir].iter().collect()
    }
}

#[derive(Debug, Eq, Hash, PartialEq)]
struct ActiveDownloadKey {
    mirror: Mirror,
    debname: String,
}

#[derive(Hash)]
struct ActiveDownloadKeyRef<'a> {
    mirror: &'a Mirror,
    debname: &'a str,
}

impl Equivalent<ActiveDownloadKey> for ActiveDownloadKeyRef<'_> {
    fn equivalent(&self, key: &ActiveDownloadKey) -> bool {
        *self.mirror == key.mirror && self.debname == key.debname
    }
}

#[derive(Debug)]
enum AbortReason {
    MirrorDownloadRate(MirrorDownloadRate),
    AlreadyLoggedJustFail,
}

#[derive(Debug)]
enum ActiveDownloadStatus {
    Init(tokio::sync::watch::Receiver<()>),
    Download(PathBuf, ContentLength, tokio::sync::watch::Receiver<()>),
    Finished(PathBuf),
    Aborted(AbortReason),
}

#[derive(Clone)]
pub(crate) struct ActiveDownloads {
    inner: Arc<
        parking_lot::RwLock<
            HashMap<ActiveDownloadKey, Arc<tokio::sync::RwLock<ActiveDownloadStatus>>>,
        >,
    >,
}

impl ActiveDownloads {
    #[must_use]
    fn new() -> Self {
        Self {
            inner: Arc::new(parking_lot::RwLock::new(HashMap::new())),
        }
    }

    #[must_use]
    fn len(&self) -> usize {
        self.inner.read().len()
    }

    #[must_use]
    fn insert(
        &self,
        mirror: &Mirror,
        debname: &str,
    ) -> (
        Option<tokio::sync::watch::Sender<()>>,
        Arc<tokio::sync::RwLock<ActiveDownloadStatus>>,
    ) {
        // Assuming concurrent requests of resources in-download are rare,
        // pre-allocate the `ActiveDownloadKey` to avoid the likely
        // allocation while holding the write-lock.
        let key = ActiveDownloadKey {
            mirror: mirror.to_owned(),
            debname: debname.to_owned(),
        };

        // Create channel and status before acquiring write lock to minimize lock scope
        let (tx, rx) = tokio::sync::watch::channel(());
        let status = Arc::new(tokio::sync::RwLock::new(ActiveDownloadStatus::Init(rx)));

        match self.inner.write().entry(key) {
            Entry::Occupied(oentry) => (None, Arc::clone(oentry.get())),
            Entry::Vacant(ventry) => {
                ventry.insert(Arc::clone(&status));
                (Some(tx), status)
            }
        }
    }

    fn remove(&self, mirror: &Mirror, debname: &str) {
        let key = ActiveDownloadKeyRef { mirror, debname };
        let was_present = self.inner.write().remove(&key);
        assert!(
            was_present.is_some(),
            "callers must own active downloads they are removing"
        );
    }

    /// Check if a download for the given mirror and debname is active.
    #[cfg(feature = "sendfile")]
    #[must_use]
    pub(crate) fn contains(&self, mirror: &Mirror, debname: &str) -> bool {
        let key = ActiveDownloadKeyRef { mirror, debname };
        self.inner.read().contains_key(&key)
    }

    #[must_use]
    fn download_size(&self) -> u64 {
        tokio::task::block_in_place(move || {
            let mut sum = 0;

            for download in self.inner.read().values() {
                let d = download.blocking_read();
                if let ActiveDownloadStatus::Download(_, size, _) = &*d {
                    sum += size.upper().get();
                }
            }

            sum
        })
    }

    #[must_use]
    fn download_count(&self) -> usize {
        tokio::task::block_in_place(move || {
            let mut count = 0;

            for download in self.inner.read().values() {
                let d = download.blocking_read();
                match &*d {
                    ActiveDownloadStatus::Init(_)
                    | ActiveDownloadStatus::Download(_, _, _)
                    | ActiveDownloadStatus::Aborted(_) => {
                        count += 1;
                    }
                    ActiveDownloadStatus::Finished(_) => (),
                }
            }

            count
        })
    }
}

async fn download_file(
    database_tx: tokio::sync::mpsc::Sender<DatabaseCommand>,
    conn_details: &ConnectionDetails,
    warn_on_override: bool,
    input: (Incoming, ContentLength),
    output: (tokio::fs::File, TempPath),
    dbarrier: DownloadBarrier,
    upstream_etag: Option<String>,
) {
    let config = global_config();

    let start = Instant::now();

    debug!(
        "Starting download of file {} from mirror {} for client {}...",
        conn_details.debname, conn_details.mirror, conn_details.client
    );

    let body = input.0;
    let content_length = input.1;

    let mut bytes = 0;
    let mut last_send_bytes = 0;
    let mut connected = true;
    let buf_size = config.buffer_size;

    // Write ETag xattr early so it survives partial downloads for resume
    if let Some(ref etag) = upstream_etag {
        write_etag(&output.0, &output.1, etag);
    }

    let mut writer = tokio::io::BufWriter::with_capacity(buf_size, output.0);
    let outpath = output.1;

    let mut body = match config.min_download_rate {
        Some(rate) => BoxBody::new(RateCheckedBody::new(
            body,
            rate,
            config.rate_check_timeframe,
        )),
        None => BoxBody::new(body.map_err(|err| Box::new(RateCheckedBodyErr::Inner(err)))),
    };

    while let Some(next) = body.frame().await {
        let frame = match next {
            Ok(f) => f,
            Err(err) => {
                match *err {
                    RateCheckedBodyErr::RateTimeout(download_rate_err) => {
                        dbarrier
                            .abort_with_reason(AbortReason::MirrorDownloadRate(
                                error::MirrorDownloadRate {
                                    download_rate_err,
                                    mirror: conn_details.mirror.clone(),
                                    debname: conn_details.debname.clone(),
                                    client_ip: conn_details.client.ip(),
                                },
                            ))
                            .await;
                    }
                    RateCheckedBodyErr::Inner(ierr) => {
                        error!(
                            "Error extracting frame from body for file {} from mirror {} (time={}, size={}, rate={}):  {}",
                            conn_details.debname,
                            conn_details.mirror,
                            HumanFmt::Time(start.elapsed().into()),
                            HumanFmt::Size(bytes),
                            HumanFmt::Rate(bytes, start.elapsed()),
                            ErrorReport::new(&ierr),
                        );
                    }
                }

                return;
            }
        };
        if let Ok(mut chunk) = frame.into_data() {
            bytes += chunk.len() as u64;

            if bytes > content_length.upper().get() {
                warn!(
                    "More bytes received than expected for file {} from mirror {}: {bytes} vs {}",
                    conn_details.debname,
                    conn_details.mirror,
                    content_length.upper()
                );
                return;
            }

            if let Err(err) = writer.write_all_buf(&mut chunk).await {
                error!("Failed to write to file `{}`:  {err}", outpath.display());
                return;
            }

            if connected && bytes > (buf_size as u64 + last_send_bytes) {
                if let Err(err) = dbarrier.ping() {
                    error!(
                        "All receivers of watch channel for file {} from mirror {} died:  {err}",
                        conn_details.debname, conn_details.mirror
                    );
                    connected = false;
                }
                last_send_bytes = bytes;
            }
        }
    }

    match content_length {
        ContentLength::Exact(size) => {
            if bytes != size.get() {
                error!(
                    "Content length mismatch: expected {} but got {} for file {} from mirror {}",
                    size.get(),
                    bytes,
                    conn_details.debname,
                    conn_details.mirror
                );
                return;
            }
        }
        ContentLength::Unknown(size) => {
            if bytes > size.get() {
                error!(
                    "Content exceeded unknown limit: got {} but limit is {} for file {} from mirror {}",
                    bytes,
                    size.get(),
                    conn_details.debname,
                    conn_details.mirror
                );
                return;
            }
        }
    }

    if let Err(err) = writer.flush().await {
        error!("Failed to write to file `{}`:  {err}", outpath.display());
        return;
    }
    drop(writer);

    let dest_dir_path = conn_details.cache_dir_path();

    if let Err(err) = tokio::fs::create_dir_all(&dest_dir_path).await
        && err.kind() != tokio::io::ErrorKind::AlreadyExists
    {
        error!(
            "Failed to create destination directory `{}`:  {err}",
            dest_dir_path.display()
        );
        return;
    }

    let dest_file_path = {
        let mut p = dest_dir_path;
        let filename = Path::new(&conn_details.debname);
        assert!(
            filename.is_relative(),
            "path construction must not contain absolute components"
        );
        p.push(filename);
        p
    };

    debug!("Saving downloaded file to `{}`", dest_file_path.display());

    {
        // Lock to block all downloading tasks, since the file from the
        // path of the downloading state is going to be moved.
        let rbarrier = dbarrier.begin_rename().await;

        /* Should only happen for concurrent downloads from aliased mirrors */
        if warn_on_override
            && tokio::fs::try_exists(&dest_file_path)
                .await
                .unwrap_or(false)
        {
            warn!(
                "Target file `{}` already exists, overriding... (aliased={})",
                dest_file_path.display(),
                conn_details.aliased_host.is_some()
            );
        }

        match tokio::fs::rename(&outpath, &dest_file_path).await {
            Ok(()) => {
                // Defuse the TempPath - the file has been successfully renamed
                TempPath::into_inner(outpath);

                rbarrier.release(dest_file_path, bytes);
            }
            Err(err) => {
                drop(rbarrier);

                error!(
                    "Failed to rename file `{}` to `{}`:  {err}",
                    outpath.display(),
                    dest_file_path.display()
                );
                // The scopeguard will remove the temp file on drop

                return;
            }
        }
    }

    let elapsed = start.elapsed();
    info!(
        "Finished download of file {} from mirror {} for client {} in {} (size={}, rate={})",
        conn_details.debname,
        conn_details.mirror,
        conn_details.client,
        HumanFmt::Time(elapsed.into()),
        HumanFmt::Size(bytes),
        HumanFmt::Rate(bytes, elapsed)
    );

    let cmd = DatabaseCommand::Download(DbCmdDownload {
        mirror: conn_details.mirror.clone(),
        debname: conn_details.debname.clone(),
        size: bytes,
        elapsed,
        client_ip: conn_details.client.ip(),
    });
    database_tx
        .send(cmd)
        .await
        .expect("database task should not die");
}

#[expect(clippy::too_many_arguments, reason = "function has only 1 caller")]
#[must_use]
async fn serve_unfinished_file(
    conn_details: ConnectionDetails,
    database_tx: tokio::sync::mpsc::Sender<DatabaseCommand>,
    mut file: tokio::fs::File,
    file_path: PathBuf,
    status: Arc<tokio::sync::RwLock<ActiveDownloadStatus>>,
    content_length: ContentLength,
    mut receiver: tokio::sync::watch::Receiver<()>,
    upstream_etag: EtagState,
) -> Response<ProxyCacheBody> {
    let config = global_config();

    // For joining clients, try reading from xattr as the download task may have already written it.
    let file_etag = match upstream_etag {
        EtagState::Some(etag) => Some(etag),
        EtagState::Failure => None,
        EtagState::Unknown => read_etag(&file, &file_path),
    };

    let md = match file.metadata().await {
        Ok(data) => data,
        Err(err) => {
            error!(
                "Failed to get metadata of file `{}`:  {err}",
                file_path.display()
            );
            return quick_response(StatusCode::INTERNAL_SERVER_ERROR, "Cache Access Error");
        }
    };

    // Cache entries are replaced on update, not overridden, so the creation time is the time the file was last modified.
    // The modified file timestamp is used to store the last up-to-date check against the upstream mirror, if creation timestamps are supported.
    let last_modified = md.created().unwrap_or_else(|_err| {
        md.modified()
            .expect("Platform should support modification timestamps via setup check")
    });

    let (tx, rx) = tokio::sync::mpsc::channel(64);

    tokio::task::spawn(async move {
        let start = Instant::now();
        debug!(
            "Starting stream task for downloading file `{}` from mirror {} with length {content_length:?} for client {}...",
            file_path.display(),
            conn_details.mirror,
            conn_details.client
        );

        let counter = client_counter::ClientDownload::new();

        let mut finished = false;
        let mut bytes = 0;
        let buf_size = config.buffer_size;

        let mut reader = tokio::io::BufReader::with_capacity(buf_size, &mut file);

        loop {
            loop {
                let mut buf = bytes::BytesMut::with_capacity(buf_size);
                let ret = match reader.read_buf(&mut buf).await {
                    Ok(0) => break, // EOF
                    Ok(r) => r,
                    Err(err) => {
                        error!("Failed to read from file `{}`:  {err}", file_path.display());
                        return;
                    }
                };

                let buf = buf.freeze();

                bytes += ret as u64;
                assert_eq!(buf.len(), ret, "buffer length must match read bytes");

                if let Err(tokio::sync::mpsc::error::SendError(_err)) = tx.send(Ok(buf)).await {
                    info!("Receiver of stream task closed; cancelling stream...");
                    return;
                }
            }

            if finished {
                break;
            }

            if let Err(tokio::sync::watch::error::RecvError { .. }) = receiver.changed().await {
                /* sender closed, either download finished or aborted */
                let st = status.read().await;
                let _: Never = match *st {
                    ActiveDownloadStatus::Finished(_) => {
                        finished = true;
                        continue;
                    }
                    ActiveDownloadStatus::Aborted(ref err) => {
                        match err {
                            AbortReason::MirrorDownloadRate(mdr) => {
                                if let Err(err) = tx
                                    .send(Err(ChannelBodyError::MirrorDownloadRate((*mdr).clone())))
                                    .await
                                {
                                    warn!("Failed to send mirror download rate:  {err}");
                                }
                            }
                            AbortReason::AlreadyLoggedJustFail => {
                                // Reason already logged
                                debug!(
                                    "Download of file `{}` aborted, cancelling stream",
                                    file_path.display()
                                );
                            }
                        }

                        return;
                    }
                    ActiveDownloadStatus::Init(_) | ActiveDownloadStatus::Download(..) => {
                        error!(
                            "Invalid download state {:?} of file `{}`, cancelling stream",
                            *st,
                            file_path.display()
                        );
                        drop(st);

                        return;
                    }
                };
            }
        }

        /* Perform cleanup before database operation */
        drop(reader);
        drop(receiver);
        drop(status);
        drop(tx);
        drop(counter);

        let elapsed = start.elapsed();
        info!(
            "Served new file {} from mirror {} for client {} in {} via channel (size={}, rate={})",
            conn_details.debname,
            conn_details.mirror,
            conn_details.client,
            HumanFmt::Time(elapsed.into()),
            HumanFmt::Size(bytes),
            HumanFmt::Rate(bytes, elapsed)
        );

        let cmd = DatabaseCommand::Delivery(DbCmdDelivery {
            mirror: conn_details.mirror,
            debname: conn_details.debname,
            size: bytes,
            elapsed,
            partial: false,
            client_ip: conn_details.client.ip(),
        });
        database_tx
            .send(cmd)
            .await
            .expect("database task should not die");
    });

    let mut response_builder = Response::builder()
        .status(StatusCode::OK)
        .header(DATE, format_http_date())
        .header(VIA, APP_VIA)
        .header(CONNECTION, "keep-alive")
        .header(CONTENT_TYPE, "application/vnd.debian.binary-package")
        .header(ACCEPT_RANGES, "bytes")
        .header(
            LAST_MODIFIED,
            HeaderValue::try_from(systemtime_to_http_datetime(last_modified))
                .expect("Http datetime is valid"),
        )
        .header(
            AGE,
            HeaderValue::from(last_modified.elapsed().map_or(0, |dur| dur.as_secs())),
        );
    if let Some(ref etag) = file_etag {
        response_builder = response_builder.header(
            ETAG,
            HeaderValue::try_from(etag.as_str()).expect("ETag is validated before passing"),
        );
    }
    if let ContentLength::Exact(size) = content_length {
        let r = response_builder
            .headers_mut()
            .expect("request should be valid")
            .append(CONTENT_LENGTH, HeaderValue::from(size.get()));
        assert!(!r, "header does not exist by previous construction");
    }

    let channel_body = ChannelBody::new(rx, content_length);

    let response = match config.min_download_rate {
        Some(min_download_rate) => {
            let checked_channel_body =
                RateCheckedBody::new(channel_body, min_download_rate, config.rate_check_timeframe);
            response_builder
                .body(ProxyCacheBody::Boxed(BoxBody::new(
                    checked_channel_body.map_err(move |err| match *err {
                        RateCheckedBodyErr::RateTimeout(download_rate_err) => {
                            Box::new(ProxyCacheError::ClientDownloadRate {
                                error: download_rate_err,
                                client_ip: conn_details.client.ip(),
                            })
                        }
                        RateCheckedBodyErr::Inner(ierr) => ierr,
                    }),
                )))
                .expect("HTTP response is valid")
        }
        None => response_builder
            .body(ProxyCacheBody::Boxed(BoxBody::new(channel_body)))
            .expect("HTTP response is valid"),
    };

    trace!("Outgoing response: {response:?}");

    response
}

#[must_use]
async fn serve_downloading_file(
    conn_details: ConnectionDetails,
    req: Request<Empty<()>>,
    database_tx: tokio::sync::mpsc::Sender<DatabaseCommand>,
    status: Arc<tokio::sync::RwLock<ActiveDownloadStatus>>,
    upstream_etag: EtagState,
) -> Response<ProxyCacheBody> {
    let mut not_found_once = false;
    let mut init_waited = false;

    loop {
        let st = status.read().await;

        match &*st {
            ActiveDownloadStatus::Aborted(_err) => {
                drop(st);
                drop(status);
                return quick_response(StatusCode::INTERNAL_SERVER_ERROR, "Download Aborted");
            }
            ActiveDownloadStatus::Init(init_rx) => {
                let mut init_rx = init_rx.clone();
                drop(st);

                assert!(
                    !init_waited,
                    "state should change once a ping is received or the downloading task dropped the sender"
                );

                // Either the state changed manually by the downloading task,
                // or the downloading task just dropped the sender.
                let _ignore = init_rx.changed().await;
                init_waited = true;
            }
            ActiveDownloadStatus::Finished(path) => {
                let path_clone = path.clone();
                drop(st);
                drop(status);
                let file = match tokio::fs::File::open(&path_clone).await {
                    Ok(f) => f,
                    Err(err) => {
                        error!(
                            "Failed to open downloaded file `{}`:  {err}",
                            path_clone.display()
                        );
                        return quick_response(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "Cache Access Failure",
                        );
                    }
                };

                return serve_cached_file(
                    conn_details,
                    &req,
                    database_tx,
                    file,
                    &path_clone,
                    EtagState::Unknown,
                )
                .await;
            }
            ActiveDownloadStatus::Download(path, content_length, receiver) => {
                // Cannot use mmap(2) since the file is not yet completely written
                let file = match tokio::fs::File::open(&path).await {
                    Ok(f) => f,
                    Err(err) if err.kind() == tokio::io::ErrorKind::NotFound => {
                        if not_found_once {
                            error!("Failed to find downloading file `{}`", path.display());
                            return quick_response(
                                StatusCode::INTERNAL_SERVER_ERROR,
                                "Download not found",
                            );
                        }
                        warn!("Failed to find downloading file `{}`", path.display());
                        not_found_once = true;
                        continue;
                    }
                    Err(err) => {
                        error!(
                            "Failed to open downloading file `{}`:  {err}",
                            path.display()
                        );
                        return quick_response(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "Cache Access Failure",
                        );
                    }
                };
                let path_clone = path.clone();
                let content_length_copy = *content_length;
                let receiver_clone = receiver.clone();
                drop(st);

                return serve_unfinished_file(
                    conn_details,
                    database_tx,
                    file,
                    path_clone,
                    status,
                    content_length_copy,
                    receiver_clone,
                    upstream_etag,
                )
                .await;
            }
        }
    }
}

enum CacheFileStat<'a> {
    Volatile {
        file: tokio::fs::File,
        file_path: &'a Path,
        local_creation_time: Option<SystemTime>,
        local_modification_time: SystemTime,
    },
    New,
}

#[must_use]
fn is_host_allowed(requested_host: &str) -> bool {
    global_config()
        .allowed_mirrors
        .iter()
        .any(|host| host.permits(requested_host))
}

#[derive(Clone, Copy, Debug)]
enum ContentLength {
    /// An exact size
    Exact(NonZero<u64>),
    /// A limit for an unknown size
    Unknown(NonZero<u64>),
}

impl ContentLength {
    #[must_use]
    const fn upper(&self) -> NonZero<u64> {
        match self {
            Self::Exact(s) | Self::Unknown(s) => *s,
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
async fn serve_new_file(
    conn_details: ConnectionDetails,
    status: Arc<tokio::sync::RwLock<ActiveDownloadStatus>>,
    init_tx: tokio::sync::watch::Sender<()>,
    req: Request<Empty<()>>,
    cfstate: CacheFileStat<'_>,
    appstate: AppState,
) -> Response<ProxyCacheBody> {
    // TODO: upstream constant
    const PROXY_CONNECTION: HeaderName = HeaderName::from_static("proxy-connection");

    #[must_use]
    fn build_fwd_request(
        uri: &Uri,
        max_age: u32,
        host: &HeaderValue,
        cfstate: &CacheFileStat<'_>,
        volatile_etag: &EtagState,
    ) -> Request<Empty<bytes::Bytes>> {
        /*
         * Request {
         *      method: GET,
         *      uri: http://deb.debian.org/debian/pool/main/g/gcc-snapshot/gcc-snapshot_20240117-1_amd64.deb,
         *      version: HTTP/1.1,
         *      headers: {
         *          "host": "deb.debian.org",
         *          "range": "bytes=34744111-",
         *          "if-range": "Thu, 18 Jan 2024 08:28:16 GMT",
         *          "user-agent": "Debian APT-HTTP/1.3 (2.7.10)"
         *      },
         *      body: Body(Empty)
         * }
         *
         * Response {
         *      status: 206,
         *      version: HTTP/1.1,
         *      headers: {
         *          "connection": "keep-alive",
         *          "content-length": "1036690709",
         *          "server": "Apache",
         *          "x-content-type-options": "nosniff",
         *          "x-frame-options": "sameorigin",
         *          "referrer-policy": "no-referrer",
         *          "x-xss-protection": "1",
         *          "permissions-policy": "interest-cohort=()",
         *          "last-modified": "Thu, 18 Jan 2024 08:28:16 GMT",
         *          "etag": "\"3fdccc44-60f3425268f75\"",
         *          "x-clacks-overhead": "GNU Terry Pratchett",
         *          "cache-control": "public, max-age=2592000",
         *          "content-type": "application/vnd.debian.binary-package",
         *          "via": "1.1 varnish, 1.1 varnish",
         *          "accept-ranges": "bytes",
         *          "age": "500053",
         *          "content-range": "bytes 34744111-1071434819/1071434820",
         *          "date": "Mon, 29 Jan 2024 12:59:10 GMT",
         *          "x-served-by": "cache-ams21080-AMS, cache-fra-eddf8230020-FRA",
         *          "x-cache": "HIT, HIT",
         *          "x-cache-hits": "33, 0",
         *          "x-timer": "S1706533151.962674,VS0,VE2"
         *      },
         *      body: Body(Streaming)
         * }
         */

        let mut request = Request::builder()
            .method(Method::GET)
            .uri(uri)
            .header(USER_AGENT, APP_USER_AGENT)
            .header(HOST, host)
            .body(Empty::new())
            .expect("request should be valid");

        if let CacheFileStat::Volatile {
            file: _,
            file_path: _,
            local_creation_time: _,
            local_modification_time,
        } = cfstate
        {
            let date_fmt = systemtime_to_http_datetime(*local_modification_time);

            let r = request.headers_mut().append(
                IF_MODIFIED_SINCE,
                HeaderValue::try_from(date_fmt).expect("HTTP datetime should be valid"),
            );
            assert!(!r, "header does not exist by previous construction");

            let r = request.headers_mut().append(
                CACHE_CONTROL,
                HeaderValue::try_from(format!("max-age={max_age}")).expect("string is valid"),
            );
            assert!(!r, "header does not exist by previous construction");

            if let EtagState::Some(etag) = volatile_etag {
                let r = request.headers_mut().append(
                    IF_NONE_MATCH,
                    HeaderValue::try_from(etag).expect("ETag is validated by read_etag"),
                );
                assert!(!r, "header does not exist by previous construction");
            }
        }

        request
    }

    let ibarrier = InitBarrier::new(
        init_tx,
        &status,
        &appstate.active_downloads,
        &conn_details.mirror,
        &conn_details.debname,
    );

    let (warn_on_override, prev_file_size) = match &cfstate {
        CacheFileStat::Volatile {
            file,
            file_path,
            local_creation_time: _,
            local_modification_time: _,
        } => {
            let size = match file.metadata().await.map(|md| md.size()) {
                Ok(s) => s,
                Err(err) => {
                    error!(
                        "Failed to get file size of file `{}`:  {err}",
                        file_path.display()
                    );
                    0
                }
            };

            (false, size)
        }
        CacheFileStat::New => (true, 0),
    };

    let mut max_age = 300;
    let mut host = None;

    for (name, value) in req.headers() {
        match name {
            &USER_AGENT | &RANGE | &IF_RANGE | &ACCEPT | &IF_MODIFIED_SINCE => (),
            n if n == PROXY_CONNECTION => (),
            &HOST => host = Some(value),
            /*
             * TODO:
             * Ignore client cache settings for now.
             * For new files they are irrelevant.
             * We assume pool files never change and for dists file we set them manually.
             */
            &CACHE_CONTROL => {
                if let Ok(s) = value.to_str() {
                    for p in s.split(',') {
                        if let Some((key, val)) = p.split_once('=')
                            && key == "max-age"
                            && let Ok(v) = val.parse::<u32>()
                        {
                            max_age = v;
                        }
                    }
                }
            }
            _ => warn_once_or_info!(
                "Unhandled HTTP header `{name}` with value `{value:?}` in request from client {}",
                conn_details.client
            ),
        }
    }
    // mark immutable
    let max_age = max_age;
    let host = match host {
        Some(h) => h,
        None => {
            // RFC 3986 §3.2.2: IPv6 addresses must be bracketed in Host headers
            &HeaderValue::from_str(&conn_details.mirror.host.format_authority(None))
                .expect("connection host should be valid")
        }
    };

    let mut req_uri = std::borrow::Cow::Borrowed(req.uri());

    if let Some(max) = global_config().max_upstream_downloads
        && appstate.active_downloads.len() > max.get()
    {
        warn_once_or_info!(
            "Max upstream downloads ({max}) exceeded, rejecting request for {} from client {}",
            conn_details.debname,
            conn_details.client
        );
        return quick_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "Too many concurrent upstream downloads",
        );
    }

    let volatile_etag = match &cfstate {
        CacheFileStat::Volatile {
            file, file_path, ..
        } => EtagState::from_option(read_etag(file, file_path)),
        CacheFileStat::New => EtagState::Unknown,
    };

    let fwd_request = build_fwd_request(&req_uri, max_age, host, &cfstate, &volatile_etag);
    trace!("Forwarded request: {fwd_request:?}");

    let mut fwd_response = match request_with_retry(&appstate.https_client, fwd_request).await {
        Ok(r) => r,
        Err(err) => {
            warn!(
                "Proxy request failed to mirror {}:  {}",
                conn_details.mirror,
                ErrorReport::new(&err)
            );
            return quick_response(StatusCode::SERVICE_UNAVAILABLE, "Proxy request failed");
        }
    };

    trace!("Forwarded response: {fwd_response:?}");

    if fwd_response.status() == StatusCode::MOVED_PERMANENTLY
        && let Some(moved_uri) = fwd_response
            .headers()
            .get(LOCATION)
            .and_then(|lc| lc.to_str().ok())
            .and_then(|lc_str| lc_str.parse::<hyper::Uri>().ok())
    {
        debug!("Requested URI: {}, Moved URI: {moved_uri:?}", req.uri());

        if moved_uri.scheme().is_some_and(|scheme| {
            *scheme == http::uri::Scheme::HTTP || *scheme == http::uri::Scheme::HTTPS
        }) && let Some(moved_host) = moved_uri.host()
            && is_host_allowed(moved_host)
        {
            req_uri = std::borrow::Cow::Owned(moved_uri);

            let redirected_request =
                build_fwd_request(&req_uri, max_age, host, &cfstate, &volatile_etag);

            trace!("Forwarded redirected request: {redirected_request:?}");

            let redirected_response =
                match request_with_retry(&appstate.https_client, redirected_request).await {
                    Ok(r) => r,
                    Err(err) => {
                        warn!(
                            "Proxy redirected request to host {host:?} failed:  {}",
                            ErrorReport::new(&err)
                        );
                        return quick_response(
                            StatusCode::SERVICE_UNAVAILABLE,
                            "Proxy request failed",
                        );
                    }
                };

            trace!("Forwarded redirected response: {redirected_response:?}");

            fwd_response = redirected_response;
        } else {
            debug!(
                "Host `{}` of moved URI not permitted",
                moved_uri.host().unwrap_or("<none>")
            );
        }
    }

    if let CacheFileStat::Volatile {
        mut file,
        file_path,
        local_creation_time,
        local_modification_time: _,
    } = cfstate
    {
        if fwd_response.status() == StatusCode::NOT_MODIFIED {
            // Cache entries are replaced on update, not overridden, so the creation time is the time the file was last modified.
            // The modified file timestamp is used to store the last up-to-date check against the upstream mirror, if creation timestamps are supported.
            // Thus only update mtime if btime is supported.
            if local_creation_time.is_some() {
                // Refactor when https://github.com/tokio-rs/tokio/issues/6368 is resolved
                file = {
                    let std_file = file.into_std().await;
                    let now = SystemTime::now();

                    let result = tokio::task::block_in_place(|| std_file.set_modified(now));

                    if let Err(err) = result {
                        error!(
                            "Failed to update modification time of file `{}`:  {}",
                            file_path.display(),
                            err
                        );
                    }

                    tokio::fs::File::from_std(std_file)
                };
            }

            ibarrier.finished(file_path.to_path_buf()).await;

            return serve_cached_file(
                conn_details,
                &req,
                appstate.database_tx,
                file,
                file_path,
                volatile_etag,
            )
            .await;
        }

        debug!(
            "File `{}` is outdated (status={}), downloading new version",
            file_path.display(),
            fwd_response.status()
        );
    }

    if fwd_response.status() != StatusCode::OK {
        let log_level = if fwd_response.status() == StatusCode::NOT_FOUND {
            Level::Debug
        } else {
            Level::Warn
        };

        log!(
            log_level,
            "Request for file {} from mirror {} with URI `{req_uri}` failed with code `{}`, got response: {fwd_response:?}",
            conn_details.debname,
            conn_details.mirror,
            fwd_response.status()
        );

        let (parts, body) = fwd_response.into_parts();

        let body = ProxyCacheBody::Boxed(BoxBody::new(
            body.map_err(|err| Box::new(ProxyCacheError::Hyper(err))),
        ));

        let mut response = Response::from_parts(parts, body);
        response
            .headers_mut()
            .append(VIA, HeaderValue::from_static(APP_VIA));

        trace!("Outgoing response: {response:?}");

        return response;
    }

    let content_length = match fwd_response.headers().get(CONTENT_LENGTH).and_then(|hv| {
        hv.to_str()
            .ok()
            .and_then(|ct| ct.parse::<NonZero<u64>>().ok())
    }) {
        Some(size) => ContentLength::Exact(size),
        None if conn_details.cached_flavor == CachedFlavor::Volatile => {
            ContentLength::Unknown(VOLATILE_UNKNOWN_CONTENT_LENGTH_UPPER)
        }
        None => {
            warn!(
                "Could not extract content-length from header for file {} from mirror {}: {fwd_response:?}",
                conn_details.debname, conn_details.mirror
            );
            return quick_response(
                StatusCode::BAD_GATEWAY,
                "Upstream resource has no content length",
            );
        }
    };

    let reservation = match global_cache_quota().try_acquire(
        content_length,
        prev_file_size,
        &conn_details.debname,
    ) {
        Ok(r) => Some(r),
        Err(cache_quota::QuotaExceeded) => {
            return quick_response(StatusCode::SERVICE_UNAVAILABLE, "Disk quota reached");
        }
    };

    let upstream_etag: Option<String> = fwd_response
        .headers()
        .get(ETAG)
        .and_then(|hv| hv.to_str().ok())
        .filter(|etag| {
            if is_valid_etag(etag) {
                true
            } else {
                warn_once_or_info!(
                    "Upstream mirror {} sent invalid ETag for {}: {etag}",
                    conn_details.mirror,
                    conn_details.debname
                );
                false
            }
        })
        .map(String::from);

    let (_parts, body) = fwd_response.into_parts();

    let filename = Path::new(&conn_details.debname);
    assert!(
        filename.is_relative(),
        "path construction must not contain absolute components"
    );
    let tmppath: PathBuf = [&global_config().cache_directory, Path::new("tmp"), filename]
        .iter()
        .collect();

    let (outfile, outpath) = match tokio_tempfile(&tmppath, 0o640).await {
        Ok((f, p)) => (f, p),
        Err(err) => {
            error!(
                "Error creating temporary file `{}`:  {err}",
                tmppath.display()
            );
            // `reservation` is dropped here, auto-reverting cache_size
            return quick_response(StatusCode::INTERNAL_SERVER_ERROR, "Cache Access Failure");
        }
    };

    info!(
        "Downloading and serving new file {} from mirror {} for client {}...",
        conn_details.debname, conn_details.mirror, conn_details.client
    );

    let dbarrier = ibarrier
        .download(outpath.to_path_buf(), content_length, reservation)
        .await;

    let cd = conn_details.clone();
    let db_tx = appstate.database_tx.clone();
    let curr_downloads = appstate.active_downloads.download_count();
    let download_etag = upstream_etag.clone();
    tokio::task::spawn(async move {
        download_file(
            db_tx,
            &cd,
            warn_on_override,
            (body, content_length),
            (outfile, outpath),
            dbarrier,
            download_etag,
        )
        .await;
    });

    let config = global_config();

    if conn_details.cached_flavor != CachedFlavor::Volatile
        && config.experimental_parallel_hack_enabled
        && config
            .experimental_parallel_hack_maxparallel
            .is_none_or(|max_parallel| curr_downloads <= max_parallel.get())
        && config
            .experimental_parallel_hack_minsize
            .is_none_or(|size| content_length.upper() > size)
    {
        #[expect(clippy::cast_precision_loss, reason = "generate probability value")]
        let p = (curr_downloads.saturating_sub(1) as f64)
            .mul_add(-config.experimental_parallel_hack_factor, 1.0)
            .max(0.0);
        let d = Bernoulli::new(p).expect("p is valid");
        let v = d.sample(&mut rand::rng());

        if v {
            debug!(
                "Trying parallel download hack for client {} and file {} with code {} and retry after value {}",
                conn_details.client,
                conn_details.debname,
                config.experimental_parallel_hack_statuscode,
                config.experimental_parallel_hack_retryafter
            );

            let mut response = Response::builder()
                .status(config.experimental_parallel_hack_statuscode)
                .header(DATE, format_http_date())
                .header(VIA, APP_VIA)
                .header(CONNECTION, "keep-alive")
                .body(ProxyCacheBody::Empty(Empty::new()))
                .expect("Response is valid");

            if config.experimental_parallel_hack_retryafter != 0 {
                response.headers_mut().append(
                    RETRY_AFTER,
                    HeaderValue::from(config.experimental_parallel_hack_retryafter),
                );
            }

            trace!("Outgoing parallel download hack response: {response:?}");

            return response;
        }
    }

    serve_downloading_file(
        conn_details,
        req,
        appstate.database_tx,
        status,
        EtagState::from_option(upstream_etag),
    )
    .await
}

/// Create a TCP connection to host:port, build a tunnel between the connection and
/// the upgraded connection
async fn tunnel(
    client: ClientInfo,
    upgraded: hyper::upgrade::Upgraded,
    host: &str,
    port: NonZero<u16>,
) -> std::io::Result<()> {
    let start = Instant::now();
    let config = global_config();

    /* Connect to remote server */
    let mut server = match tokio::time::timeout(
        config.http_timeout,
        tokio::net::TcpStream::connect((host, port.get())),
    )
    .await
    {
        Ok(result) => result?,
        Err(tokio::time::error::Elapsed { .. }) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "tunnel connect timed out",
            ));
        }
    };
    let mut upgraded = TokioIo::new(upgraded);

    /* Proxying data */
    let bufsize = config.buffer_size;

    // not rate-checked
    let (from_client, from_server) =
        tokio::io::copy_bidirectional_with_sizes(&mut upgraded, &mut server, bufsize, bufsize)
            .await?;

    info!(
        "Tunneled client {client} wrote {} and received {} from {host}:{port} in {}",
        HumanFmt::Size(from_client),
        HumanFmt::Size(from_server),
        HumanFmt::Time(start.elapsed().into())
    );

    Ok(())
}

#[must_use]
pub(crate) async fn process_cache_request(
    conn_details: ConnectionDetails,
    req: Request<Empty<()>>,
    appstate: AppState,
) -> Response<ProxyCacheBody> {
    let cache_path = {
        let mut p = conn_details.cache_dir_path();
        let filename = Path::new(&conn_details.debname);
        assert!(
            filename.is_relative(),
            "path construction must not contain absolute components"
        );
        p.push(filename);
        p
    };

    match tokio::fs::File::open(&cache_path).await {
        Ok(file) => {
            trace!(
                "File {} found, serving {} version...",
                cache_path.display(),
                match conn_details.cached_flavor {
                    CachedFlavor::Permanent => "permanent",
                    CachedFlavor::Volatile => "volatile",
                }
            );
            match conn_details.cached_flavor {
                CachedFlavor::Volatile => {
                    serve_volatile_file(conn_details, req, file, &cache_path, appstate).await
                }
                CachedFlavor::Permanent => {
                    serve_cached_file(
                        conn_details,
                        &req,
                        appstate.database_tx,
                        file,
                        &cache_path,
                        EtagState::Unknown,
                    )
                    .await
                }
            }
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            let (init_tx, status) = appstate
                .active_downloads
                .insert(&conn_details.mirror, &conn_details.debname);

            trace!(
                "File {} not found, serving {} version...",
                cache_path.display(),
                if init_tx.is_some() {
                    "in-download"
                } else {
                    "new"
                }
            );

            if let Some(init_tx) = init_tx {
                serve_new_file(
                    conn_details,
                    status,
                    init_tx,
                    req,
                    CacheFileStat::New,
                    appstate,
                )
                .await
            } else {
                info!(
                    "Serving file {} already in download from mirror {} for client {}...",
                    conn_details.debname, conn_details.mirror, conn_details.client
                );
                serve_downloading_file(
                    conn_details,
                    req,
                    appstate.database_tx,
                    status,
                    EtagState::Unknown,
                )
                .await
            }
        }
        Err(err) => {
            error!("Failed to open file `{}`:  {err}", cache_path.display());
            quick_response(
                hyper::StatusCode::INTERNAL_SERVER_ERROR,
                "Cache Access Failure",
            )
        }
    }
}

#[must_use]
fn connect_response(
    client: ClientInfo,
    req: Request<hyper::body::Incoming>,
) -> Response<ProxyCacheBody> {
    let config = global_config();

    {
        let allowed_proxy_clients = config.allowed_proxy_clients.as_slice();
        let client_ip = client.ip();
        if !allowed_proxy_clients.is_empty()
            && !allowed_proxy_clients
                .iter()
                .any(|ac| ac.contains(&client_ip))
        {
            warn_once_or_info!("Unauthorized proxy client {client}");
            return quick_response(hyper::StatusCode::FORBIDDEN, "Unauthorized client");
        }
    }

    if !config.https_tunnel_enabled {
        info!("Rejecting https tunnel request for client {client}");
        return quick_response(StatusCode::FORBIDDEN, "HTTPS tunneling disabled");
    }

    /*
     * Received an HTTP request like:
     * ```
     * CONNECT www.domain.com:443 HTTP/1.1
     * Host: www.domain.com:443
     * Proxy-Connection: Keep-Alive
     * ```
     *
     * When HTTP method is CONNECT we should return an empty body
     * then we can eventually upgrade the connection and talk a new protocol.
     *
     * Note: only after client received an empty body with STATUS_OK can the
     * connection be upgraded, so we can't return a response inside
     * `on_upgrade` future.
     */

    let Some((host, port)) = req.uri().authority().and_then(|a| {
        a.port_u16()
            .and_then(NonZero::new)
            .map(|p| (a.host().to_string(), p))
    }) else {
        warn_once_or_info!(
            "Invalid CONNECT address from client {client}: {}",
            req.uri()
        );
        return quick_response(StatusCode::BAD_REQUEST, "Invalid CONNECT address");
    };

    if !config.https_tunnel_allowed_ports.is_empty()
        && config
            .https_tunnel_allowed_ports
            .binary_search(&port)
            .is_err()
    {
        info!("Rejecting https tunnel request for client {client} to not permitted port {port}");
        return quick_response(StatusCode::FORBIDDEN, "HTTPS tunneling disabled");
    }

    if !config.https_tunnel_allowed_mirrors.is_empty()
        && config
            .https_tunnel_allowed_mirrors
            .binary_search_by(|d| str::cmp(d, host.as_str()))
            .is_err()
    {
        info!(
            "Rejecting https tunnel request for client {client} due to not permitted host {host}"
        );
        return quick_response(StatusCode::FORBIDDEN, "HTTPS tunneling disabled");
    }

    let tunnel_guard = if let Some(max) = config.https_tunnel_max_connections_per_client {
        if let Some(guard) = tunnel_limiter::try_acquire(client.ip(), max) {
            Some(guard)
        } else {
            info!(
                "Rejecting https tunnel request for client {client}: \
                     concurrent connection limit ({max}) reached"
            );
            return quick_response(
                StatusCode::TOO_MANY_REQUESTS,
                "Too many concurrent HTTPS tunnel connections",
            );
        }
    } else {
        None
    };

    info!("Using un-cached tunnel for client {client} to {host}:{port}");

    tokio::task::spawn(async move {
        let _tunnel_guard = tunnel_guard;
        match hyper::upgrade::on(req).await {
            Ok(upgraded) => {
                if let Err(err) = tunnel(client, upgraded, &host, port).await {
                    if err.kind() == ErrorKind::NotConnected {
                        info!(
                            "Error tunneling connection for client {client} to {host}:{port}:  {err}"
                        );
                    } else if err.kind() == ErrorKind::ConnectionReset {
                        warn!(
                            "Error tunneling connection for client {client} to {host}:{port}:  {err}"
                        );
                    } else {
                        error!(
                            "Error tunneling connection for client {client} to {host}:{port}:  {err}"
                        );
                    }
                }
            }
            Err(err) => {
                error!(
                    "Error upgrading connection for client {client} to {host}:{port}:  {}",
                    ErrorReport::new(&err)
                );
            }
        }
    });

    let response = Response::builder()
        .header(SERVER, APP_NAME)
        .header(DATE, format_http_date())
        .body(ProxyCacheBody::Empty(Empty::new()))
        .expect("HTTP response is valid");

    trace!("Outgoing response: {response:?}");

    response
}

pub(crate) fn authorize_cache_access(
    client: &ClientInfo,
    requested_host: String,
) -> Result<DomainName, (http::StatusCode, &'static str)> {
    let config = global_config();

    let allowed_proxy_clients = config.allowed_proxy_clients.as_slice();
    let client_ip = client.ip();
    if !allowed_proxy_clients.is_empty()
        && !allowed_proxy_clients
            .iter()
            .any(|ac| ac.contains(&client_ip))
    {
        warn_once_or_info!("Unauthorized proxy client {client}");
        return Err((StatusCode::FORBIDDEN, "Unauthorized client"));
    }

    let requested_host = match DomainName::new(requested_host) {
        Ok(d) => d,
        Err(rh) => {
            warn_once_or_info!("Unsupported host `{}`", rh.escape_debug());
            return Err((StatusCode::BAD_REQUEST, "Unsupported host"));
        }
    };

    if !is_host_allowed(&requested_host) {
        warn_once_or_info!("Unauthorized host {requested_host}");
        return Err((StatusCode::FORBIDDEN, "Unauthorized host"));
    }

    Ok(requested_host)
}

#[inline]
async fn pre_process_client_request_wrapper(
    client: ClientInfo,
    req: Request<hyper::body::Incoming>,
    appstate: AppState,
) -> Result<Response<ProxyCacheBody>, Infallible> {
    Ok(pre_process_client_request(client, req, appstate).await)
}

#[must_use]
async fn pre_process_client_request(
    client: ClientInfo,
    req: Request<hyper::body::Incoming>,
    appstate: AppState,
) -> Response<ProxyCacheBody> {
    trace!("Incoming request: {req:?}");

    let config = global_config();

    match req.method() {
        &Method::CONNECT => return connect_response(client, req),
        &Method::GET => {}
        m => {
            warn_once_or_info!("Unsupported request method {m} from client {client}");
            return quick_response(
                hyper::StatusCode::METHOD_NOT_ALLOWED,
                "Method not supported",
            );
        }
    }

    // Proxy GET requests always use http://, HTTPS goes through CONNECT.
    // Reject any other scheme (e.g. ftp://, file://).
    if let Some(scheme) = req.uri().scheme()
        && *scheme != http::uri::Scheme::HTTP
    {
        warn_once_or_info!("Unsupported URI scheme `{scheme}` from client {client}");
        return quick_response(hyper::StatusCode::BAD_REQUEST, "Unsupported URI scheme");
    }

    let requested_host =
        if let Some(h) = req.uri().authority().map(hyper::http::uri::Authority::host) {
            h.to_owned()
        } else {
            // RFC 7230 §5.4: A server MUST respond with a 400 status code to any
            // HTTP/1.1 request that lacks a Host header field.
            // HTTP/1.0 did not require Host, so only enforce for 1.1+.
            if req.version() == hyper::Version::HTTP_11
                && !req.headers().contains_key(hyper::header::HOST)
            {
                return quick_response(hyper::StatusCode::BAD_REQUEST, "Missing Host header");
            }

            {
                let allowed_webif_clients = config
                    .allowed_webif_clients
                    .as_ref()
                    .unwrap_or(&config.allowed_proxy_clients);
                let client_ip = client.ip();
                if !allowed_webif_clients.is_empty()
                    && !allowed_webif_clients
                        .iter()
                        .any(|ac| ac.contains(&client_ip))
                {
                    warn_once_or_info!("Unauthorized web-interface access by client {client}");
                    return quick_response(hyper::StatusCode::FORBIDDEN, "Unauthorized client");
                }
            }

            return serve_web_interface(req, &appstate).await;
        };

    let requested_port = match req.uri().port_u16() {
        Some(port) => {
            let Some(port) = NonZero::new(port) else {
                warn_once_or_info!("Unsupported request port 0 from client {client}");
                return quick_response(hyper::StatusCode::BAD_REQUEST, "Invalid port");
            };
            Some(port)
        }
        None => None,
    };

    let requested_host = match authorize_cache_access(&client, requested_host) {
        Ok(rh) => rh,
        Err((status, msg)) => return quick_response(status, msg),
    };

    let aliased_host = config
        .aliases
        .iter()
        .find(|alias| alias.aliases.binary_search(&requested_host).is_ok())
        .map(|alias| &alias.main);

    if req.body().size_hint().exact() != Some(0) {
        warn_once_or_info!(
            "Request from client {client} has non empty body, not forwarding body: {req:?}"
        );
    }
    let (parts, _body) = req.into_parts();
    let req = Request::from_parts(parts, Empty::new());

    let requested_path = req.uri().path();

    trace!(
        "Requested host: `{requested_host}`; Aliased host: `{aliased_host:?}`; Requested path: `{requested_path}`"
    );

    if let Some(resource) = parse_request_path(requested_path) {
        #[derive(Clone, Copy)]
        enum ValidateKind {
            MirrorPath,
            Distribution,
            Component,
            Architecture,
            Filename,
        }

        impl Display for ValidateKind {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(match self {
                    Self::MirrorPath => "mirror path",
                    Self::Distribution => "distribution",
                    Self::Component => "component",
                    Self::Architecture => "architecture",
                    Self::Filename => "filename",
                })
            }
        }

        #[inline]
        #[must_use]
        fn validate(name: &str, kind: ValidateKind) -> bool {
            match kind {
                ValidateKind::MirrorPath => valid_mirrorname(name),
                ValidateKind::Distribution => valid_distribution(name),
                ValidateKind::Component => valid_component(name),
                ValidateKind::Architecture => valid_architecture(name),
                ValidateKind::Filename => valid_filename(name),
            }
        }

        macro_rules! validate {
            ($name: ident, $kind: expr) => {
                let encoded = $name;
                let kind = $kind;
                let decoded = match urlencoding::decode(encoded) {
                    Ok(s) => s,
                    Err(err) => {
                        warn_once_or_info!("Failed to decode {kind} `{encoded}`:  {err}");
                        return quick_response(StatusCode::BAD_REQUEST, "Unsupported URL encoding");
                    }
                };
                if !validate(&decoded, kind) {
                    warn_once_or_info!("Unsupported {kind} `{decoded}`");
                    return quick_response(hyper::StatusCode::BAD_REQUEST, "Unsupported request");
                }

                let $name = decoded;
            };
        }

        match resource {
            ResourceFile::Pool {
                mirror_path,
                filename,
            } => {
                validate!(mirror_path, ValidateKind::MirrorPath);
                validate!(filename, ValidateKind::Filename);

                // TODO: cache .dsc?
                let is_deb = filename.ends_with(".deb");

                if is_deb {
                    trace!("Decoded mirror path: `{mirror_path}`; Decoded filename: `{filename}`");

                    let conn_details = ConnectionDetails {
                        client,
                        mirror: Mirror {
                            host: requested_host,
                            port: requested_port,
                            path: mirror_path.into_owned(),
                        },
                        aliased_host,
                        debname: filename.into_owned(),
                        cached_flavor: CachedFlavor::Permanent,
                        subdir: None,
                    };

                    return process_cache_request(conn_details, req, appstate).await;
                }

                warn_once_or_info!(
                    "Unsupported pool file extension in filename `{filename}` from client {client}"
                );
            }
            ResourceFile::Release {
                mirror_path,
                distribution,
                filename,
            } => {
                validate!(mirror_path, ValidateKind::MirrorPath);
                validate!(distribution, ValidateKind::Distribution);
                validate!(filename, ValidateKind::Filename);

                trace!(
                    "Decoded mirror path: `{mirror_path}`; Decoded distribution: `{distribution}`; Decoded filename: `{filename}`"
                );

                let conn_details = ConnectionDetails {
                    client,
                    mirror: Mirror {
                        host: requested_host,
                        port: requested_port,
                        path: mirror_path.into_owned(),
                    },
                    aliased_host,
                    debname: format!("{distribution}_{filename}"),
                    cached_flavor: CachedFlavor::Volatile,
                    subdir: Some(Path::new("dists")),
                };

                return process_cache_request(conn_details, req, appstate).await;
            }
            ResourceFile::ByHash {
                mirror_path,
                filename,
            } => {
                validate!(mirror_path, ValidateKind::MirrorPath);
                validate!(filename, ValidateKind::Filename);

                trace!("Decoded mirror path: `{mirror_path}`; Decoded filename: `{filename}`");

                let conn_details = ConnectionDetails {
                    client,
                    mirror: Mirror {
                        host: requested_host,
                        port: requested_port,
                        path: mirror_path.into_owned(),
                    },
                    aliased_host,
                    debname: filename.into_owned(),
                    cached_flavor: CachedFlavor::Permanent,
                    subdir: Some(Path::new("dists/by-hash")),
                };

                // files requested by hash shouldn't be volatile
                return process_cache_request(conn_details, req, appstate).await;
            }
            ResourceFile::Icon {
                mirror_path,
                distribution,
                component,
                filename,
            }
            | ResourceFile::Sources {
                mirror_path,
                distribution,
                component,
                filename,
            }
            | ResourceFile::Translation {
                mirror_path,
                distribution,
                component,
                filename,
            } => {
                validate!(mirror_path, ValidateKind::MirrorPath);
                validate!(distribution, ValidateKind::Distribution);
                validate!(component, ValidateKind::Component);
                validate!(filename, ValidateKind::Filename);

                trace!(
                    "Decoded mirror path: `{mirror_path}`; Decoded distribution: `{distribution}`; Decoded component: `{component}`; Decoded filename: `{filename}`"
                );

                let conn_details = ConnectionDetails {
                    client,
                    mirror: Mirror {
                        host: requested_host,
                        port: requested_port,
                        path: mirror_path.into_owned(),
                    },
                    aliased_host,
                    debname: format!("{distribution}_{component}_{filename}"),
                    cached_flavor: CachedFlavor::Volatile,
                    subdir: Some(Path::new("dists/")),
                };

                return process_cache_request(conn_details, req, appstate).await;
            }
            ResourceFile::Packages {
                mirror_path,
                distribution,
                component,
                architecture,
                filename,
            } => {
                validate!(mirror_path, ValidateKind::MirrorPath);
                validate!(distribution, ValidateKind::Distribution);
                validate!(component, ValidateKind::Component);
                validate!(architecture, ValidateKind::Architecture);
                validate!(filename, ValidateKind::Filename);

                trace!(
                    "Decoded mirror path: `{mirror_path}`; \
                    Decoded distribution: `{distribution}`; \
                    Decoded component: `{component}`; \
                    Decoded architecture: `{architecture}`; \
                    Decoded filename: `{filename}`"
                );

                let conn_details = ConnectionDetails {
                    client,
                    mirror: Mirror {
                        host: requested_host,
                        port: requested_port,
                        path: mirror_path.into_owned(),
                    },
                    aliased_host,
                    debname: format!("{distribution}_{component}_{architecture}_{filename}"),
                    cached_flavor: CachedFlavor::Volatile,
                    subdir: Some(Path::new("dists")),
                };

                match architecture.as_ref() {
                    // TODO: cache some of them?
                    "dep11" | "i18n" | "source" => (),
                    _ => {
                        let origin = Origin {
                            mirror: conn_details.mirror.clone(),
                            distribution: distribution.into_owned(),
                            component: component.into_owned(),
                            architecture: architecture.into_owned(),
                        };
                        let cmd = DatabaseCommand::Origin(DbCmdOrigin { origin });
                        appstate
                            .database_tx
                            .send(cmd)
                            .await
                            .expect("database task should not die");
                    }
                }

                return process_cache_request(conn_details, req, appstate).await;
            }
        }
    }

    assert_eq!(req.method(), Method::GET, "Filtered at function start");

    /*
     * Simple proxy (without any caching)
     *
     * http://deb.debian.org/debian-debug/dists/sid-debug/main/binary-i386/Packages.diff/T-2024-09-24-2005.48-F-2024-09-23-2021.00.gz
     * http://deb.debian.org/debian/dists/unstable/main/i18n/Translation-en.diff/T-2024-10-03-0804.49-F-2024-10-02-2011.04.gz
     * http://deb.debian.org/debian/dists/sid/main/source/Sources.diff/T-2024-10-03-1409.04-F-2024-10-03-1409.04.gz
     */
    #[expect(
        clippy::items_after_statements,
        reason = "keep definition close to single use"
    )]
    fn ignore_uncached_path(uri_path: &str) -> bool {
        uri_path.contains("/Packages.diff/T-")
            || uri_path.contains("/Translation-en.diff/T-")
            || uri_path.contains("/Sources.diff/T-")
    }

    if ignore_uncached_path(requested_path) {
        info!(
            "Proxying (without caching) request {} for client {client}",
            req.uri()
        );
    } else {
        warn_once_or_info!(
            "Proxying (without caching) request {} for client {client}",
            req.uri()
        );

        let mut uncacheables = UNCACHEABLES.get().expect("Initialized in main()").write();

        // always delete to keep recent entries fresh
        if let Some((idx, (_h, _p))) = uncacheables
            .iter()
            .enumerate()
            .find(|(_idx, (h, p))| *h == requested_host && *p == requested_path)
        {
            let entry = uncacheables.remove(idx).expect("entry exists");
            debug_assert_eq!(
                entry.0, requested_host,
                "requested_host was used as lookup key"
            );
            debug_assert_eq!(
                entry.1, requested_path,
                "requested_path was used as lookup key"
            );

            uncacheables.push(entry);
        } else {
            uncacheables.push((requested_host.clone(), requested_path.to_owned()));
        }
    }

    let (mut parts, _body) = req.into_parts();
    parts
        .headers
        .insert(USER_AGENT, HeaderValue::from_static(APP_USER_AGENT));

    let mut parts_cloned = parts.clone();

    // TODO: tweak http version?
    let fwd_request = Request::from_parts(parts, Empty::new());

    trace!("Forwarded request: {fwd_request:?}");

    let fwd_response = match request_with_retry(&appstate.https_client, fwd_request).await {
        Ok(r) => r,
        Err(err) => {
            warn!(
                "Proxy request to host {requested_host} failed for client {client}:  {}",
                ErrorReport::new(&err)
            );
            return quick_response(StatusCode::SERVICE_UNAVAILABLE, "Proxy request failed");
        }
    };

    trace!("Forwarded response: {fwd_response:?}");

    if (fwd_response.status().is_success() || fwd_response.status().is_redirection())
        && let Some(origin) = Origin::from_path(
            parts_cloned.uri.path(),
            requested_host.clone(),
            requested_port,
        )
    {
        debug!("Extracted origin: {origin:?}");

        match origin.architecture.as_str() {
            // TODO: cache some of them?
            "dep11" | "i18n" | "source" => (),
            _ => {
                let cmd = DatabaseCommand::Origin(DbCmdOrigin { origin });
                appstate
                    .database_tx
                    .send(cmd)
                    .await
                    .expect("database task should not die");
            }
        }
    }

    if fwd_response.status() == StatusCode::MOVED_PERMANENTLY
        && let Some(moved_uri) = fwd_response
            .headers()
            .get(LOCATION)
            .and_then(|lc| lc.to_str().ok())
            .and_then(|lc_str| lc_str.parse::<hyper::Uri>().ok())
    {
        debug!(
            "Requested URI: {}, Moved URI: {moved_uri}",
            parts_cloned.uri
        );

        if moved_uri.scheme().is_some_and(|scheme| {
            *scheme == http::uri::Scheme::HTTP || *scheme == http::uri::Scheme::HTTPS
        }) && moved_uri.host().is_some_and(is_host_allowed)
        {
            parts_cloned.uri = moved_uri;
            let redirected_request = Request::from_parts(parts_cloned, Empty::new());

            trace!("Redirected request: {redirected_request:?}");

            let redirected_response = match request_with_retry(
                &appstate.https_client,
                redirected_request,
            )
            .await
            {
                Ok(r) => r,
                Err(err) => {
                    warn!(
                        "Redirected proxy request to host {requested_host} failed for client {client}:  {}",
                        ErrorReport::new(&err)
                    );
                    return quick_response(StatusCode::SERVICE_UNAVAILABLE, "Proxy request failed");
                }
            };

            trace!("Redirected response: {redirected_response:?}");

            let (parts, body) = redirected_response.into_parts();

            let body = ProxyCacheBody::Boxed(BoxBody::new(
                body.map_err(|err| Box::new(ProxyCacheError::Hyper(err))),
            ));

            let mut response = Response::from_parts(parts, body);
            response
                .headers_mut()
                .append(VIA, HeaderValue::from_static(APP_VIA));

            trace!("Outgoing response: {response:?}");

            return response;
        }
    }

    let mut response = fwd_response.map(|body| {
        ProxyCacheBody::Boxed(BoxBody::new(
            body.map_err(|err| Box::new(ProxyCacheError::Hyper(err))),
        ))
    });
    response
        .headers_mut()
        .append(VIA, HeaderValue::from_static(APP_VIA));

    trace!("Outgoing response: {response:?}");

    response
}

mod client_counter {
    use std::sync::atomic::{AtomicUsize, Ordering};

    static CONNECTED_CLIENTS: AtomicUsize = AtomicUsize::new(0);
    static CLIENT_DOWNLOADS: AtomicUsize = AtomicUsize::new(0);

    #[must_use]
    pub(crate) fn connected_clients() -> usize {
        CONNECTED_CLIENTS.load(Ordering::Relaxed)
    }

    pub(super) struct ClientCounter {
        _private: (),
    }

    impl ClientCounter {
        pub(super) fn new() -> Self {
            CONNECTED_CLIENTS.fetch_add(1, Ordering::Relaxed);
            Self { _private: () }
        }
    }

    impl Drop for ClientCounter {
        fn drop(&mut self) {
            CONNECTED_CLIENTS.fetch_sub(1, Ordering::Relaxed);
        }
    }

    #[must_use]
    pub(crate) fn active_client_downloads() -> usize {
        CLIENT_DOWNLOADS.load(Ordering::Relaxed)
    }

    #[derive(Debug)]
    pub(super) struct ClientDownload {
        _private: (),
    }

    impl ClientDownload {
        pub(super) fn new() -> Self {
            CLIENT_DOWNLOADS.fetch_add(1, Ordering::Relaxed);
            Self { _private: () }
        }
    }

    impl Drop for ClientDownload {
        fn drop(&mut self) {
            CLIENT_DOWNLOADS.fetch_sub(1, Ordering::Relaxed);
        }
    }
}

mod tunnel_limiter {
    use hashbrown::HashMap;
    use parking_lot::Mutex;
    use std::net::IpAddr;
    use std::num::NonZero;

    static TUNNEL_CONNECTIONS: std::sync::LazyLock<Mutex<HashMap<IpAddr, usize>>> =
        std::sync::LazyLock::new(|| Mutex::new(HashMap::new()));

    /// Try to acquire a tunnel slot for the given client IP.
    /// Returns `Some(TunnelGuard)` if under the limit, `None` if at capacity.
    pub(super) fn try_acquire(client_ip: IpAddr, max: NonZero<usize>) -> Option<TunnelGuard> {
        let mut map = TUNNEL_CONNECTIONS.lock();
        let count = map.entry(client_ip).or_insert(0);
        if *count >= max.get() {
            return None;
        }
        *count += 1;
        drop(map);
        Some(TunnelGuard { client_ip })
    }

    pub(super) struct TunnelGuard {
        client_ip: IpAddr,
    }

    impl Drop for TunnelGuard {
        fn drop(&mut self) {
            let mut map = TUNNEL_CONNECTIONS.lock();
            if let hashbrown::hash_map::Entry::Occupied(mut entry) = map.entry(self.client_ip) {
                let count = entry.get_mut();
                *count -= 1;
                if *count == 0 {
                    entry.remove();
                }
            }
        }
    }
}

async fn main_loop() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let config = global_config();

    let mut addr = SocketAddr::from((config.bind_addr, config.bind_port.get()));

    #[cfg(all(feature = "tls_hyper", not(feature = "tls_rustls")))]
    let https_connector = HttpsConnector::new();

    #[cfg(feature = "tls_rustls")]
    let https_connector = {
        /* Set a process wide default crypto provider. */
        //let _ = rustls::crypto::ring::default_provider().install_default();
        if rustls::crypto::aws_lc_rs::default_provider()
            .install_default()
            .is_err()
        {
            warn!("Failed to install aws-lc as default crypto provider");
        }

        let tls_cfg = rustls::ClientConfig::builder()
            .with_native_roots()?
            .with_no_client_auth();
        hyper_rustls::HttpsConnectorBuilder::new()
            .with_tls_config(tls_cfg)
            .https_or_http()
            .enable_http1()
            .build()
    };

    let mut timeout_connector = hyper_timeout::TimeoutConnector::new(https_connector);
    let http_timeout = match config.http_timeout {
        x if x.is_zero() => None,
        x => Some(x),
    };
    debug!("Using http timeout of {http_timeout:?}");
    timeout_connector.set_connect_timeout(http_timeout);
    timeout_connector.set_read_timeout(http_timeout);
    timeout_connector.set_write_timeout(http_timeout);
    let https_client =
        hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
            .build(timeout_connector);

    let database = Database::connect(&config.database_path, config.database_slow_timeout)
        .await
        .map_err(|err| {
            error!(
                "Error creating database `{}`:  {err}",
                config.database_path.display()
            );
            err
        })?;

    database.init_tables().await.map_err(|err| {
        error!(
            "Error initializing database `{}`:  {err}",
            config.database_path.display()
        );
        err
    })?;

    database.cleanup_invalid_rows().await.map_err(|err| {
        error!("Failed to clean up invalid database rows:  {err}");
        err
    })?;

    // Database background task
    let (db_task_tx, db_task_rx) = tokio::sync::mpsc::channel(config.db_channel_capacity.get());
    {
        let database = database.clone();
        tokio::task::spawn(db_loop(database, db_task_rx));
    }

    // Initial cache scan task
    {
        let database = database.clone();
        tokio::task::spawn(async move {
            if let Ok(cache_size) = task_cache_scan(&database).await {
                let rd = RUNTIMEDETAILS.get().expect("global set in main()");

                rd.cache_quota.add(cache_size);

                let disk_quota = rd.config.disk_quota;

                match disk_quota {
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
            } else {
                warn!("Startup cache size unset");
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
                                let severity = if response.status().is_server_error() {
                                    Level::Warn
                                } else {
                                    // ignore response, we just care about connection success
                                    Level::Trace
                                };
                                log!(severity,
                                    "Response for host {authority} of initial scheme cache request:  {response:?}"
                                );
                            }
                            Err(err) => {
                                // request_with_retry() has already logged the error
                                debug!("Failed to query host {authority} to initialize scheme cache:  {}", ErrorReport::new(&err));
                            }
                        }
                    }
                })
                .buffer_unordered(MAX_CONCURRENT_REQUESTS)
                .collect::<Vec<_>>()
                .await;

            trace!(
                "Scheme cache:  {:?}",
                &*SCHEME_CACHE.get().expect("initialized in main()").read()
            );

            debug!("Scheme cache initialization task finished");
        });
    }

    let active_downloads = ActiveDownloads::new();

    let mut term_signal = tokio::signal::unix::signal(SignalKind::terminate())?;
    let mut usr1_signal = tokio::signal::unix::signal(SignalKind::user_defined1())?;

    let first_cleanup = tokio::time::Instant::now() + Duration::from_hours(1);
    let mut cleanup_interval = tokio::time::interval_at(first_cleanup, Duration::from_hours(24));

    let appstate = AppState {
        database,
        database_tx: db_task_tx,
        https_client,
        active_downloads,
    };

    let listener = match TcpListener::bind(addr).await {
        Ok(x) => x,
        Err(err) => {
            if config.bind_addr != Ipv6Addr::UNSPECIFIED {
                error!("Error binding on {addr}:  {err}");
                return Err(err.into());
            }

            // Fallback to IPv4 to avoid errors when IPv6 is not available and the default configuration is used.
            addr = SocketAddr::from((Ipv4Addr::UNSPECIFIED, config.bind_port.get()));
            TcpListener::bind(addr).await.map_err(|err| {
                error!("Error binding fallback on {addr}:  {err}");
                err
            })?
        }
    };
    info!("Ready and listening on http://{addr}");

    loop {
        trace!(
            "Active downloads ({}):  {:?}",
            appstate.active_downloads.len(),
            &*appstate.active_downloads.inner.read()
        );

        let next = tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                info!("SIGINT received, stopping...");
                return Ok(());
            },
            _ = term_signal.recv() => {
                info!("SIGTERM received, stopping...");
                return Ok(());
            },
            _ = cleanup_interval.tick() => {
                info!("Daily cleanup issued...");
                let appstate = appstate.clone();
                tokio::task::spawn( async move {
                    if let Err(err) = task_cleanup(&appstate).await {
                        error!("Error performing cleanup task:  {err}");
                    }
                });
                continue;
            },
            _ = usr1_signal.recv() => {
                info!("SIGUSR1 received, issuing cleanup...");
                cleanup_interval.reset();
                let appstate = appstate.clone();
                tokio::task::spawn( async move {
                    if let Err(err) = task_cleanup(&appstate).await {
                        error!("Error performing cleanup task:  {err}");
                    }
                });
                continue;
            },
            n = listener.accept() => n
        };

        let (stream, client) = next
            .map(|(stream, client)| (stream, ClientInfo::new(client)))
            .map_err(|err| {
                error!("Error accepting connection:  {err}");
                err
            })?;

        let client_counter = client_counter::ClientCounter::new();

        info!("New client connection from {client}");
        let client_start = Instant::now();

        let appstate = appstate.clone();
        tokio::task::spawn(async move {
            #[cfg(feature = "sendfile")]
            sendfile_conn::handle_sendfile_connection(stream, client, appstate).await;

            #[cfg(not(feature = "sendfile"))]
            handle_hyper_connection(stream, client, appstate).await;

            info!(
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

    #[cfg(feature = "mmap")]
    macro_rules! feature_mmap {
        () => {
            "true"
        };
    }

    #[cfg(not(feature = "mmap"))]
    macro_rules! feature_mmap {
        () => {
            "false"
        };
    }

    #[cfg(feature = "sendfile")]
    macro_rules! feature_sendfile {
        () => {
            "true"
        };
    }

    #[cfg(not(feature = "sendfile"))]
    macro_rules! feature_sendfile {
        () => {
            "false"
        };
    }

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
        )
    }
}

pub(crate) async fn handle_hyper_connection<T>(stream: T, client: ClientInfo, appstate: AppState)
where
    T: tokio::io::AsyncRead
        + tokio::io::AsyncWrite
        + std::marker::Unpin
        + std::marker::Send
        + 'static,
{
    #[must_use]
    fn is_iokind(err: &hyper::Error, kind: std::io::ErrorKind) -> bool {
        if let Some(err) = std::error::Error::source(&err)
            && let Some(ioerr) = err.downcast_ref::<std::io::Error>()
            && ioerr.kind() == kind
        {
            return true;
        }

        false
    }

    #[must_use]
    fn is_connection_reset(err: &hyper::Error) -> bool {
        is_iokind(err, std::io::ErrorKind::ConnectionReset)
    }

    #[must_use]
    fn is_shutdown_disconnect(err: &hyper::Error) -> bool {
        is_iokind(err, std::io::ErrorKind::NotConnected)
    }

    #[must_use]
    fn is_broken_pipe(err: &hyper::Error) -> bool {
        is_iokind(err, std::io::ErrorKind::BrokenPipe)
    }

    #[must_use]
    fn is_timeout(err: &hyper::Error) -> Option<&ProxyCacheError> {
        let pe = err.source()?.downcast_ref::<ProxyCacheError>()?;

        if matches!(pe, ProxyCacheError::ClientDownloadRate { .. })
            || matches!(pe, ProxyCacheError::MirrorDownloadRate(_))
        {
            Some(pe)
        } else {
            None
        }
    }

    if let Err(err) = http1::Builder::new()
        .serve_connection(
            TokioIo::new(stream),
            service_fn(move |req| {
                pre_process_client_request_wrapper(client, req, appstate.clone())
            }),
        )
        .with_upgrades()
        .await
    {
        if err.is_incomplete_message() || is_connection_reset(&err) {
            info!("Connection to client {client} cancelled");
        } else if is_shutdown_disconnect(&err) {
            info!(
                "Improper connection shutdown for client {client}:  {}",
                ErrorReport::new(&err)
            );
        } else if is_broken_pipe(&err) {
            info!(
                "Broken pipe for client {client}:  {}",
                ErrorReport::new(&err)
            );
        } else if let Some(perr) = is_timeout(&err) {
            info!("{perr}");
        } else {
            error!(
                "Error serving connection for client {client}:  {}",
                ErrorReport::new(&err)
            );
        }
    }
}

#[derive(Parser)]
#[command(author, version, long_version(get_features(true)), about)]
struct Cli {
    /// Log file path (log to file instead of stdout [default])
    #[arg(long, value_name = "PATH")]
    log_file: Option<PathBuf>,
    /// Logging level
    #[arg(short, long, value_name = "SEVERITY")]
    log_level: Option<LevelFilter>,
    /// Configuration file path
    #[arg(
        short = 'c',
        long,
        default_value = config::DEFAULT_CONFIGURATION_PATH,
        value_name = "PATH"
    )]
    config_path: PathBuf,
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

static RUNTIMEDETAILS: OnceLock<RuntimeDetails> = OnceLock::new();
static LOGSTORE: OnceLock<LogStore> = OnceLock::new();
static UNCACHEABLES: OnceLock<parking_lot::RwLock<RingBuffer<(DomainName, String)>>> =
    OnceLock::new();

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
    let args = Cli::parse();

    let (config, cfg_fallback, config_warnings) = Config::new(&args.config_path)?;

    let config_log_level = config.log_level;
    let config_logstore_capacity = config.logstore_capacity;
    let config_disk_quota = config.disk_quota;

    RUNTIMEDETAILS
        .set(RuntimeDetails {
            start_time: time::OffsetDateTime::now_utc(),
            config,
            cache_quota: cache_quota::CacheQuota::new(0, config_disk_quota),
        })
        .expect("Initial set in main() should succeed");

    let output_log_level = args.log_level.unwrap_or(config_log_level);

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
        .set(LogStore::new(config_logstore_capacity))
        .expect("Initial set in main() should succeed");

    UNCACHEABLES
        .set(parking_lot::RwLock::new(RingBuffer::new(nonzero!(20))))
        .expect("Initial set in main() should succeed");

    SCHEME_CACHE
        .set(parking_lot::RwLock::new(HashMap::new()))
        .expect("Initial set in main() should succeed");

    let internal_logger = WriteLogger::new(
        LevelFilter::Warn,
        internal_log_config,
        LOGSTORE.get().expect("Should be set").clone(),
    );

    if let Some(ref log_path) = args.log_file {
        #[expect(
            clippy::print_stderr,
            reason = "print to stderr for log file open error"
        )]
        let log_file_handle = match OpenOptions::new().append(true).create(true).open(log_path) {
            Ok(file) => file,
            Err(err) => {
                eprintln!("Failed to open log file `{}`:  {err}", log_path.display());
                std::process::exit(1);
            }
        };

        CombinedLogger::init(vec![
            WriteLogger::new(output_log_level, output_log_config, log_file_handle),
            internal_logger,
        ])?;
    } else {
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

    debug!("Logger initialized");
    trace!("Tracing enabled");

    if cfg_fallback {
        info!(
            "Default configuration file `{}` not found, using defaults",
            args.config_path.display()
        );
    }

    for warning in config_warnings {
        warn!("Configuration:  {warning}");
    }

    debug!("Configuration: {:?}", global_config());

    if nix::unistd::getuid().is_root() {
        if args.permit_running_daemon_as_root {
            warn!("!! Running as root is not recommended !!");
        } else {
            error!("Running as root is not recommended and not permitted by default");
            std::process::exit(1);
        }
    }

    if global_config().allowed_mirrors.is_empty() {
        warn!("No mirror allowed, consider setting option 'allowed_mirrors'");
    }

    info!(
        "Using cache directory `{}`",
        global_config().cache_directory.display()
    );

    task_setup().map_err(|err| {
        error!("Error during setup:  {err}");
        err
    })?;

    #[expect(clippy::print_stderr, reason = "print to stderr for panic hook")]
    std::panic::set_hook(Box::new(move |info| {
        error!("{info}");
        eprintln!("{info}");
    }));

    scopeguard::defer! {
        info!("Stopped.");
    }

    let runtime = Builder::new_multi_thread()
        .enable_all()
        .thread_name("apt-cacher-rs-w")
        .build()
        .expect("Should succeed");

    drop(args);

    runtime.block_on(async { main_loop().await })
}
