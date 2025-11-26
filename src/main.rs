#![cfg_attr(not(feature = "mmap"), forbid(unsafe_code))]
#![allow(clippy::too_many_lines)]

#[cfg(not(any(feature = "tls_hyper", feature = "tls_rustls")))]
compile_error!("Either feature \"tls_hyper\" or \"tls_rustls\" must be enabled for this crate.");

#[cfg(all(feature = "tls_hyper", feature = "tls_rustls"))]
compile_error!("Feature \"tls_hyper\" and \"tls_rustls\" are mutually exclusive.");

mod channel_body;
mod config;
mod database;
mod database_task;
mod deb_mirror;
mod error;
mod http_range;
mod humanfmt;
mod log_once;
mod logstore;
mod rate_checked_body;
mod ringbuffer;
mod task_cache_scan;
mod task_cleanup;
mod task_setup;
mod web_interface;

use std::borrow::Borrow;
use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::convert::Infallible;
use std::error::Error;
use std::fmt::Debug;
use std::hash::Hash;
use std::hash::Hasher;
use std::io::ErrorKind;
#[cfg(feature = "mmap")]
use std::net::IpAddr;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::num::NonZero;
use std::os::unix::fs::MetadataExt as _;
use std::path::Path;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::OnceLock;
#[cfg(not(feature = "mmap"))]
use std::task::Poll::Pending;
use std::task::Poll::Ready;
use std::time::Duration;
use std::time::Instant;
use std::time::SystemTime;

use channel_body::ChannelBody;
use channel_body::ChannelBodyError;
use clap::Parser;
#[cfg(not(feature = "mmap"))]
use futures_util::TryStreamExt as _;
use http_body_util::{BodyExt as _, Empty, Full, combinators::BoxBody};
use http_range::http_parse_range;
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
use hyper::header::HOST;
use hyper::header::HeaderName;
use hyper::header::HeaderValue;
use hyper::header::IF_MODIFIED_SINCE;
use hyper::header::IF_RANGE;
use hyper::header::LAST_MODIFIED;
use hyper::header::LOCATION;
use hyper::header::RANGE;
use hyper::header::RETRY_AFTER;
use hyper::header::SERVER;
use hyper::header::USER_AGENT;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode, body::Body};
#[cfg(feature = "tls_rustls")]
use hyper_rustls::{ConfigBuilderExt as _, HttpsConnector};
#[cfg(all(feature = "tls_hyper", not(feature = "tls_rustls")))]
use hyper_tls::HttpsConnector;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioIo;
use log::{LevelFilter, debug, error, info, trace, warn};
#[cfg(feature = "mmap")]
use memmap2::{Advice, Mmap, MmapOptions};
use pin_project::pin_project;
#[cfg(not(feature = "mmap"))]
use pin_project::pinned_drop;
use rand::Rng as _;
use rand::SeedableRng as _;
use rand::distr::Alphanumeric;
use rand::distr::Bernoulli;
use rand::prelude::Distribution as _;
use rand::rngs::SmallRng;
use rate_checked_body::RateCheckedBody;
use rate_checked_body::RateCheckedBodyErr;
use simplelog::CombinedLogger;
use simplelog::ConfigBuilder;
use simplelog::WriteLogger;
use simplelog::{ColorChoice, TermLogger, TerminalMode};
use tokio::io::AsyncReadExt as _;
#[cfg(not(feature = "mmap"))]
use tokio::io::AsyncSeekExt as _;
use tokio::io::AsyncWriteExt as _;
use tokio::net::TcpListener;
use tokio::runtime::Builder;
use tokio::signal::unix::SignalKind;

use crate::config::Config;
use crate::config::DomainName;
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
use crate::error::MirrorDownloadRate;
use crate::error::ProxyCacheError;
use crate::http_range::http_datetime_to_systemtime;
use crate::http_range::systemtime_to_http_datetime;
use crate::humanfmt::HumanFmt;
use crate::logstore::LogStore;
use crate::ringbuffer::RingBuffer;
use crate::task_cache_scan::task_cache_scan;
use crate::task_cleanup::task_cleanup;
use crate::task_setup::task_setup;
use crate::web_interface::serve_web_interface;

type Client = hyper_util::client::legacy::Client<
    hyper_timeout::TimeoutConnector<HttpsConnector<HttpConnector>>,
    Empty<bytes::Bytes>,
>;

const APP_NAME: &str = env!("CARGO_PKG_NAME");
const APP_VERSION: &str = env!("CARGO_PKG_VERSION");
const APP_USER_AGENT: &str = concat!(env!("CARGO_PKG_NAME"), "/", env!("CARGO_PKG_VERSION"),);

const RETENTION_TIME: Duration = Duration::from_secs(8 * 7 * 24 * 60 * 60); /* 8 weeks */

const VOLATILE_UNKNOWN_CONTENT_LENGTH_UPPER: NonZero<u64> = nonzero!(1024 * 1024); /* 1MiB */

async fn tokio_mkstemp(
    path: &Path,
    mode: u32,
) -> Result<(tokio::fs::File, PathBuf), tokio::io::Error> {
    let mut rng = SmallRng::from_os_rng();

    let mut buf = path.to_path_buf();

    let mut tries = 0;
    loop {
        const MAX_TRIES: u32 = 10;

        let s: String = (&mut rng)
            .sample_iter(Alphanumeric)
            .take(6)
            .map(char::from)
            .collect();

        assert!(buf.set_extension(s));

        match tokio::fs::File::options()
            .create_new(true)
            .write(true)
            .mode(mode)
            .open(&buf)
            .await
        {
            Ok(file) => return Ok((file, buf)),
            Err(err) if err.kind() == tokio::io::ErrorKind::AlreadyExists => {
                tries += 1;
                if tries > MAX_TRIES {
                    return Err(err);
                }
                assert!(buf.set_extension(""));
                continue;
            }
            Err(err) => return Err(err),
        }
    }
}

pub(crate) async fn request_with_retry(
    client: &Client,
    request: Request<Empty<bytes::Bytes>>,
) -> Result<Response<Incoming>, hyper_util::client::legacy::Error> {
    const MAX_RETRIES: u32 = 5;

    debug_assert_eq!(
        request.body().size_hint().exact(),
        Some(0),
        "Invariant of Empty"
    );

    let (parts, _body) = request.into_parts();

    let mut tries = 0;
    let mut sleep_prev = 1;
    let mut sleep_curr = 1;

    loop {
        let req_clone = Request::from_parts(parts.clone(), Empty::new());

        match client.request(req_clone).await {
            Ok(response) => return Ok(response),
            Err(err) if !err.is_connect() => {
                warn_once_or_info!(
                    "Request of internal client to {} failed:  {err}  --  {err:?}",
                    parts.uri
                );
                return Err(err);
            }
            Err(err) => {
                if tries >= MAX_RETRIES {
                    return Err(err);
                }

                tries += 1;

                tokio::time::sleep(Duration::from_secs(sleep_curr)).await;
                (sleep_curr, sleep_prev) = (sleep_curr + sleep_prev, sleep_curr);

                continue;
            }
        }
    }
}

#[must_use]
fn quick_response<T: Into<bytes::Bytes>>(
    status: hyper::StatusCode,
    message: T,
) -> Response<ProxyCacheBody> {
    Response::builder()
        .status(status)
        .header(SERVER, HeaderValue::from_static(APP_NAME))
        .body(ProxyCacheBody::Full(Full::new(message.into())))
        .expect("Response is valid")
}

#[must_use]
fn not_modified_response(
    client_modified_since: &HeaderValue,
    file_modified_time: SystemTime,
) -> Option<Response<ProxyCacheBody>> {
    if let Some(client_modified_time) = client_modified_since
        .to_str()
        .ok()
        .and_then(http_datetime_to_systemtime)
        && client_modified_time >= file_modified_time
    {
        /*
         * Response {
         *     status: 304,
         *     version: HTTP/1.1,
         *     headers: {
         *         "connection": "keep-alive",
         *         "date": "Sat, 08 Jun 2024 12:50:39 GMT",
         *         "via": "1.1 varnish",
         *         "etag": "\"306ed-61a5ca11810f3\"",
         *         "age": "104",
         *         "x-served-by": "cache-fra-eddf8230031-FRA",
         *         "x-cache": "HIT",
         *         "x-cache-hits": "1",
         *         "x-timer": "S1717851040.758717,VS0,VE1"
         *     },
         *     body: Body(Empty)
         * }
         */

        let response = Response::builder()
            .status(StatusCode::NOT_MODIFIED)
            .header(CONNECTION, HeaderValue::from_static("keep-alive"))
            .header(SERVER, HeaderValue::from_static(APP_NAME))
            .header(
                AGE,
                HeaderValue::try_from(format!(
                    "{}",
                    file_modified_time.elapsed().map_or(0, |dur| dur.as_secs())
                ))
                .expect("string is valid"),
            )
            .header(DATE, systemtime_to_http_datetime(SystemTime::now()))
            .body(ProxyCacheBody::Empty(Empty::new()))
            .expect("HTTP response is valid");

        trace!("Outgoing response of up-to-date cached file: {response:?}");

        return Some(response);
    }

    None
}

#[cfg(not(feature = "mmap"))]
/* Adopted from http_body_util::StreamBody */
#[pin_project(PinnedDrop)]
#[derive(Debug)]
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
}

#[cfg(not(feature = "mmap"))]
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
        }
    }
}

#[cfg(not(feature = "mmap"))]
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

#[cfg(not(feature = "mmap"))]
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
                    "Served cached file {} from mirror {}{} for client {} in {} (size={}, rate={})",
                    cd.debname,
                    cd.mirror,
                    aliased,
                    cd.client.ip().to_canonical(),
                    HumanFmt::Time(duration),
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
            } else if transferred_bytes == 0 && duration < Duration::from_secs(1) {
                info!(
                    "Aborted serving cached file {} from mirror {}{} for client {} after {}:  {}",
                    cd.debname,
                    cd.mirror,
                    aliased,
                    cd.client.ip().to_canonical(),
                    HumanFmt::Time(duration),
                    error.unwrap_or_else(|| String::from("unknown reason")),
                );
            } else {
                warn!(
                    "Failed to serve cached file {} from mirror {}{} for client {} after {} (size={}, transferred={}, rate={}):  {}",
                    cd.debname,
                    cd.mirror,
                    aliased,
                    cd.client.ip().to_canonical(),
                    HumanFmt::Time(duration),
                    HumanFmt::Size(size),
                    HumanFmt::Size(transferred_bytes),
                    HumanFmt::Rate(transferred_bytes, duration),
                    error.unwrap_or_else(|| String::from("unknown reason")),
                );
            }
        });
    }
}

#[derive(Debug)]
#[pin_project(project = EnumProj)]
enum ProxyCacheBody {
    #[cfg(feature = "mmap")]
    Mmap(#[pin] MmapBody),
    #[cfg(feature = "mmap")]
    MmapRateChecked(#[pin] RateCheckedBody<MmapData>, IpAddr),
    Boxed(#[pin] BoxBody<bytes::Bytes, ProxyCacheError>),
    Full(#[pin] Full<bytes::Bytes>),
    Empty(#[pin] Empty<bytes::Bytes>),
}

impl Body for ProxyCacheBody {
    type Data = ProxyCacheBodyData;

    type Error = ProxyCacheError;

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
                .map_err(|rerr| match rerr {
                    RateCheckedBodyErr::DownloadRate(download_rate_err) => {
                        ProxyCacheError::ClientDownloadRate(error::ClientDownloadRate {
                            download_rate_err,
                            client_ip: *client_ip,
                        })
                    }
                    RateCheckedBodyErr::Hyper(herr) => ProxyCacheError::Hyper(herr),
                    RateCheckedBodyErr::ProxyCache(perr) => perr,
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
#[derive(Debug)]
struct MmapBody {
    mapping: Option<Mmap>,
    position: usize,
    length: usize,
    partial: bool,
    start: Instant,
    database_tx: Option<tokio::sync::mpsc::Sender<DatabaseCommand>>,
    conn_details: Option<ConnectionDetails>,
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
            mapping: Some(mapping),
            position: 0,
            length,
            partial,
            start: Instant::now(),
            database_tx: Some(database_tx),
            conn_details: Some(conn_details),
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
                    "Served cached file {} from mirror {}{} for client {} in {} (size={}, rate={})",
                    cd.debname,
                    cd.mirror,
                    aliased,
                    cd.client.ip().to_canonical(),
                    HumanFmt::Time(elapsed),
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
            } else if transferred_bytes == 0 && elapsed < Duration::from_secs(1) {
                info!(
                    "Aborted serving cached file {} from mirror {}{} for client {} after {}",
                    cd.debname,
                    cd.mirror,
                    aliased,
                    cd.client.ip().to_canonical(),
                    HumanFmt::Time(elapsed),
                );
            } else {
                warn!(
                    "Failed to serve cached file {} from mirror {}{} for client {} after {} (size={}, transferred={}, rate={})",
                    cd.debname,
                    cd.mirror,
                    aliased,
                    cd.client.ip().to_canonical(),
                    HumanFmt::Time(elapsed),
                    HumanFmt::Size(size),
                    HumanFmt::Size(transferred_bytes),
                    HumanFmt::Rate(transferred_bytes, elapsed),
                );
            }
        });
    }
}

#[cfg(feature = "mmap")]
#[derive(Debug)]
struct MmapData {
    mapping: Mmap,
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
        assert!(cnt <= self.remaining);
        self.position += cnt;
        self.remaining -= cnt;
    }
}

#[cfg(feature = "mmap")]
impl Body for MmapBody {
    type Data = MmapData;
    type Error = Infallible;

    fn is_end_stream(&self) -> bool {
        debug_assert!(self.position <= self.length);
        self.position == self.length
    }

    fn size_hint(&self) -> SizeHint {
        debug_assert!(self.position <= self.length);
        SizeHint::with_exact((self.length - self.position) as u64)
    }

    fn poll_frame(
        mut self: Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        if self.is_end_stream() {
            return Ready(None);
        }

        // TODO: split frames?
        let frame = Frame::data(MmapData {
            mapping: self
                .mapping
                .take()
                .expect("initialized in new() and only one frame is created"),
            position: self.position,
            remaining: self.length,
        });

        self.as_mut().position = self.length;

        Ready(Some(Ok(frame)))
    }
}

#[must_use]
async fn serve_cached_file(
    conn_details: ConnectionDetails,
    req: Request<Empty<()>>,
    database_tx: tokio::sync::mpsc::Sender<DatabaseCommand>,
    file: tokio::fs::File,
    file_path: &Path,
) -> Response<ProxyCacheBody> {
    let metadata = match file.metadata().await {
        Ok(m) => m,
        Err(err) => {
            error!(
                "Error getting metadata of cached file `{}`:  {err}",
                file_path.display()
            );
            return quick_response(StatusCode::INTERNAL_SERVER_ERROR, "Cache Access Failure");
        }
    };

    let file_size = metadata.len();
    let local_modification_time = metadata
        .modified()
        .expect("platform should support modification time");

    if let Some(client_modified_since) = req.headers().get(IF_MODIFIED_SINCE)
        && let Some(response) =
            not_modified_response(client_modified_since, local_modification_time)
    {
        info!(
            "Serving info about up-to-date cached file {} from mirror {} for client {}",
            conn_details.debname,
            conn_details.mirror,
            conn_details.client.ip().to_canonical()
        );

        return response;
    }

    let aliased = match conn_details.aliased_host {
        Some(alias) => format!(" aliased to host {alias}"),
        None => String::new(),
    };
    info!(
        "Serving cached file {} from mirror {}{} for client {}...",
        conn_details.debname,
        conn_details.mirror,
        aliased,
        conn_details.client.ip().to_canonical()
    );

    let (http_status, content_start, content_length, content_range, partial) = if let Some(range) =
        req.headers().get(RANGE).and_then(|val| val.to_str().ok())
        && let Some((content_range, start, content_length)) = http_parse_range(
            range,
            req.headers()
                .get(IF_RANGE)
                .and_then(|val| val.to_str().ok()),
            file_size,
            local_modification_time,
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
    let content_length: usize = match content_length.try_into() {
        Ok(c) => c,
        Err(_err) => {
            error!(
                "Content length of {} for file `{}` from mirror {}{} for client {} is too large",
                content_length,
                file_path.display(),
                conn_details.mirror,
                aliased,
                conn_details.client.ip().to_canonical()
            );
            return quick_response(StatusCode::INTERNAL_SERVER_ERROR, "Cache Access Failure");
        }
    };

    #[cfg(feature = "mmap")]
    let response = serve_cached_file_mmap(
        conn_details,
        database_tx,
        file,
        file_path,
        local_modification_time,
        http_status,
        content_length,
        content_start,
        content_range,
        partial,
    )
    .await;
    #[cfg(not(feature = "mmap"))]
    let response = serve_cached_file_buf(
        conn_details,
        database_tx,
        file,
        file_path,
        file_size,
        local_modification_time,
        http_status,
        content_length,
        content_start,
        content_range,
        partial,
    )
    .await;

    response
}

#[cfg(feature = "mmap")]
#[expect(clippy::too_many_arguments)]
async fn serve_cached_file_mmap(
    conn_details: ConnectionDetails,
    database_tx: tokio::sync::mpsc::Sender<DatabaseCommand>,
    file: tokio::fs::File,
    file_path: &Path,
    modification_date: SystemTime,
    http_status: StatusCode,
    content_length: usize,
    content_start: u64,
    content_range: Option<String>,
    partial: bool,
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

        debug_assert_eq!(memory_map.len(), content_length);

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

    let body = match global_config().min_download_rate {
        Some(rate) => ProxyCacheBody::MmapRateChecked(
            RateCheckedBody::new(memory_body.map_err(|never| match never {}), rate),
            client_ip,
        ),
        None => ProxyCacheBody::Mmap(memory_body),
    };

    serve_cached_file_response(
        http_status,
        modification_date,
        content_length as u64,
        body,
        content_range,
    )
}

#[cfg(not(feature = "mmap"))]
#[expect(clippy::too_many_arguments)]
async fn serve_cached_file_buf(
    conn_details: ConnectionDetails,
    database_tx: tokio::sync::mpsc::Sender<DatabaseCommand>,
    mut file: tokio::fs::File,
    file_path: &Path,
    file_size: u64,
    modification_date: SystemTime,
    http_status: StatusCode,
    content_length: u64,
    start: u64,
    content_range: Option<String>,
    partial: bool,
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
    let body = ProxyCacheBody::Boxed(delivery_body.map_err(ProxyCacheError::Io).boxed());

    serve_cached_file_response(
        http_status,
        modification_date,
        content_length,
        body,
        content_range,
    )
}

fn serve_cached_file_response(
    http_status: StatusCode,
    modification_date: SystemTime,
    content_length: u64,
    body: ProxyCacheBody,
    content_range: Option<String>,
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
        .header(CONNECTION, HeaderValue::from_static("keep-alive"))
        .header(CONTENT_LENGTH, HeaderValue::from(content_length))
        .header(
            CONTENT_TYPE,
            HeaderValue::from_static("application/vnd.debian.binary-package"),
        )
        .header(
            LAST_MODIFIED,
            HeaderValue::try_from(systemtime_to_http_datetime(modification_date))
                .expect("date string is valid"),
        )
        .header(ACCEPT_RANGES, HeaderValue::from_static("bytes"))
        .header(SERVER, HeaderValue::from_static(APP_NAME))
        .body(body)
        .expect("HTTP response is valid");

    if let Some(ct) = content_range {
        let r = response.headers_mut().append(
            CONTENT_RANGE,
            ct.try_into().expect("content range string is valid"),
        );
        assert!(!r);
    }

    trace!("Outgoing response of cached file: {response:?}");

    response
}

#[derive(Clone)]
struct AppState {
    database: Database,
    database_tx: tokio::sync::mpsc::Sender<DatabaseCommand>,
    https_client: Client,
    active_downloads: ActiveDownloads,
}

#[must_use]
async fn serve_volatile_file(
    conn_details: ConnectionDetails,
    req: Request<Empty<()>>,
    file: tokio::fs::File,
    file_path: &Path,
    appstate: AppState,
) -> Response<ProxyCacheBody> {
    let (init_tx, status) = appstate
        .active_downloads
        .insert(conn_details.mirror.clone(), conn_details.debname.clone());

    let Some(init_tx) = init_tx else {
        info!(
            "Serving file {} already in download from mirror {} for client {}...",
            conn_details.debname,
            conn_details.mirror,
            conn_details.client.ip().to_canonical()
        );
        return serve_downloading_file(conn_details, req, appstate.database_tx, status).await;
    };

    let local_modification_time = match file.metadata().await {
        Ok(data) => data
            .modified()
            .expect("Platform should support modification timestamps"),
        Err(err) => {
            error!(
                "Failed to get modification timestamp of file `{}`:  {err}",
                file_path.display()
            );
            return quick_response(StatusCode::INTERNAL_SERVER_ERROR, "Cache Access Failure");
        }
    };

    serve_new_file(
        conn_details,
        status,
        init_tx,
        req,
        CacheFileStat::Volatile((file, file_path, local_modification_time)),
        appstate,
    )
    .await
}

#[derive(Clone, Debug)]
struct ConnectionDetails {
    client: SocketAddr,
    mirror: Mirror,
    aliased_host: Option<&'static DomainName>,
    debname: String,
    subdir: Option<&'static Path>,
    volatile: bool,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct ActiveDownloadKeyRef<'a> {
    mirror: &'a Mirror,
    debname: &'a str,
}

#[derive(Debug, Eq, Hash, PartialEq)]
struct ActiveDownloadKey {
    mirror: Mirror,
    debname: String,
}

trait AsActiveDownloadKeyRef {
    #[must_use]
    fn as_key_ref(&self) -> ActiveDownloadKeyRef<'_>;
}

impl AsActiveDownloadKeyRef for ActiveDownloadKey {
    fn as_key_ref(&self) -> ActiveDownloadKeyRef<'_> {
        ActiveDownloadKeyRef {
            mirror: &self.mirror,
            debname: &self.debname,
        }
    }
}

impl AsActiveDownloadKeyRef for ActiveDownloadKeyRef<'_> {
    fn as_key_ref(&self) -> ActiveDownloadKeyRef<'_> {
        *self
    }
}

impl PartialEq for dyn AsActiveDownloadKeyRef + '_ {
    fn eq(&self, other: &Self) -> bool {
        self.as_key_ref() == other.as_key_ref()
    }
}

impl Eq for dyn AsActiveDownloadKeyRef + '_ {}

impl Hash for dyn AsActiveDownloadKeyRef + '_ {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.as_key_ref().hash(state);
    }
}

impl<'a> Borrow<dyn AsActiveDownloadKeyRef + 'a> for ActiveDownloadKey {
    fn borrow(&self) -> &(dyn AsActiveDownloadKeyRef + 'a) {
        self
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

#[derive(Clone, Debug)]
struct ActiveDownloads {
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
        mirror: Mirror,
        debname: String,
    ) -> (
        Option<tokio::sync::watch::Sender<()>>,
        Arc<tokio::sync::RwLock<ActiveDownloadStatus>>,
    ) {
        let key = ActiveDownloadKey { mirror, debname };
        let mut ads = self.inner.write();

        match ads.entry(key) {
            Entry::Occupied(occupied_entry) => (None, Arc::clone(occupied_entry.get())),
            Entry::Vacant(vacant_entry) => {
                let (tx, rx) = tokio::sync::watch::channel(());
                let status = Arc::new(tokio::sync::RwLock::new(ActiveDownloadStatus::Init(rx)));
                vacant_entry.insert(Arc::clone(&status));
                (Some(tx), status)
            }
        }
    }

    fn remove(&self, mirror: &Mirror, debname: &str) {
        let key = ActiveDownloadKeyRef { mirror, debname };
        let was_present = self
            .inner
            .write()
            .remove(&key as &dyn AsActiveDownloadKeyRef);
        assert!(was_present.is_some());
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
    status: &Arc<tokio::sync::RwLock<ActiveDownloadStatus>>,
    input: (Incoming, ContentLength),
    output: (tokio::fs::File, PathBuf),
    tx: tokio::sync::watch::Sender<()>,
) {
    trace!(
        "Starting download of file {} from mirror {} for client {}...",
        conn_details.debname,
        conn_details.mirror,
        conn_details.client.ip().to_canonical()
    );
    let start = Instant::now();

    let body = input.0;
    let content_length = input.1;

    let mut bytes = 0;
    let mut last_send_bytes = 0;
    let mut connected = true;
    let buf_size = global_config().buffer_size;

    let mut writer = tokio::io::BufWriter::with_capacity(buf_size, output.0);

    let mut body = match global_config().min_download_rate {
        Some(rate) => BoxBody::new(RateCheckedBody::new(
            body.map_err(RateCheckedBodyErr::Hyper),
            rate,
        )),
        None => BoxBody::new(body.map_err(RateCheckedBodyErr::Hyper)),
    };

    while let Some(next) = body.frame().await {
        let frame = match next {
            Ok(f) => f,
            Err(err) => {
                match err {
                    RateCheckedBodyErr::DownloadRate(download_rate_err) => {
                        *status.write().await = ActiveDownloadStatus::Aborted(
                            AbortReason::MirrorDownloadRate(error::MirrorDownloadRate {
                                download_rate_err,
                                mirror: conn_details.mirror.clone(),
                                debname: conn_details.debname.clone(),
                                client_ip: conn_details.client.ip(),
                            }),
                        );
                    }
                    RateCheckedBodyErr::Hyper(herr) => {
                        error!(
                            "Error extracting frame from body for file {} from mirror {}:  {herr}",
                            conn_details.debname, conn_details.mirror
                        );
                        *status.write().await =
                            ActiveDownloadStatus::Aborted(AbortReason::AlreadyLoggedJustFail);
                    }
                    RateCheckedBodyErr::ProxyCache(perr) => {
                        error!(
                            "Error extracting frame from body for file {} from mirror {}:  {perr}",
                            conn_details.debname, conn_details.mirror
                        );
                        *status.write().await =
                            ActiveDownloadStatus::Aborted(AbortReason::AlreadyLoggedJustFail);
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
                *status.write().await =
                    ActiveDownloadStatus::Aborted(AbortReason::AlreadyLoggedJustFail);
                return;
            }

            if let Err(err) = writer.write_all_buf(&mut chunk).await {
                error!("Error writing to file `{}`:  {err}", output.1.display());
                *status.write().await =
                    ActiveDownloadStatus::Aborted(AbortReason::AlreadyLoggedJustFail);
                return;
            }

            if connected && bytes > (buf_size as u64 + last_send_bytes) {
                if let Err(err) = tx.send(()) {
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
        ContentLength::Exact(size) => assert_eq!(bytes, size.get()),
        ContentLength::Unknown(size) => assert!(bytes <= size.get()),
    }

    if let Err(err) = writer.flush().await {
        error!("Error writing to file `{}`:  {err}", output.1.display());
        *status.write().await = ActiveDownloadStatus::Aborted(AbortReason::AlreadyLoggedJustFail);
        return;
    }
    drop(writer);

    let cache_dir = &global_config().cache_directory;

    let dest_dir: PathBuf = [
        cache_dir,
        Path::new(
            &conn_details
                .aliased_host
                .unwrap_or(&conn_details.mirror.host),
        ),
        Path::new(&conn_details.mirror.path),
        conn_details.subdir.unwrap_or_else(|| Path::new("")),
    ]
    .iter()
    .collect();

    if let Err(err) = tokio::fs::create_dir_all(&dest_dir).await
        && err.kind() != tokio::io::ErrorKind::AlreadyExists
    {
        error!(
            "Failed to create destination directory `{}`:  {err}",
            dest_dir.display()
        );
        *status.write().await = ActiveDownloadStatus::Aborted(AbortReason::AlreadyLoggedJustFail);
        return;
    }

    let dest_path: PathBuf = [
        cache_dir,
        Path::new(
            &conn_details
                .aliased_host
                .unwrap_or(&conn_details.mirror.host),
        ),
        Path::new(&conn_details.mirror.path),
        conn_details.subdir.unwrap_or_else(|| Path::new("")),
        Path::new(&conn_details.debname),
    ]
    .iter()
    .collect();

    debug!("Saving downloaded file to `{}`", dest_path.display());

    {
        let mut locked_status = status.write().await;

        /* Should only happen for concurrent downloads from aliased mirrors */
        if warn_on_override && tokio::fs::try_exists(&dest_path).await.unwrap_or(false) {
            warn!(
                "Target file `{}` already exists, overriding... (aliased={})",
                dest_path.display(),
                conn_details.aliased_host.is_some()
            );
        }

        match tokio::fs::rename(&output.1, &dest_path).await {
            Ok(()) => {
                {
                    let diff =
                        content_length.upper().get().checked_sub(bytes).expect(
                            "should not download more bytes than announced via ContentLength",
                        );
                    if diff != 0 {
                        trace!(
                            "Adjusting cache size by {diff} for downloaded file `{}`",
                            dest_path.display()
                        );

                        let mut mg_cache_size = RUNTIMEDETAILS
                            .get()
                            .expect("global is set in main()")
                            .cache_size
                            .lock();
                        *mg_cache_size = mg_cache_size
                            .checked_sub(diff)
                            .expect("cache size should not underflow");
                    }
                }
                *locked_status = ActiveDownloadStatus::Finished(dest_path);
            }
            Err(err) => {
                error!(
                    "Failed to rename file `{}` to `{}`:  {err}",
                    output.1.display(),
                    dest_path.display()
                );
                *locked_status = ActiveDownloadStatus::Aborted(AbortReason::AlreadyLoggedJustFail);
            }
        }
    }

    /* Drop sender before database work */
    drop(tx);

    let elapsed = start.elapsed();
    info!(
        "Finished download of file {} from mirror {} for client {} in {} (size={}, rate={})",
        conn_details.debname,
        conn_details.mirror,
        conn_details.client.ip().to_canonical(),
        HumanFmt::Time(elapsed),
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

#[must_use]
async fn serve_unfinished_file(
    conn_details: ConnectionDetails,
    database_tx: tokio::sync::mpsc::Sender<DatabaseCommand>,
    mut file: tokio::fs::File,
    file_path: PathBuf,
    status: Arc<tokio::sync::RwLock<ActiveDownloadStatus>>,
    content_length: ContentLength,
    mut receiver: tokio::sync::watch::Receiver<()>,
) -> Response<ProxyCacheBody> {
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

    let create_time = match md.created() {
        Ok(data) => data,
        Err(created_err) => {
            info_once!(
                "Failed to get create timestamp for file `{}`:  {created_err}",
                file_path.display()
            );
            match md.modified() {
                Ok(data) => data,
                Err(modified_err) => {
                    error!(
                        "Failed to get create and modify timestamp of file `{}`:  {created_err}  //  {modified_err}",
                        file_path.display()
                    );
                    return quick_response(StatusCode::INTERNAL_SERVER_ERROR, "Cache Access Error");
                }
            }
        }
    };

    let (tx, rx) = tokio::sync::mpsc::channel(64);

    tokio::task::spawn(async move {
        let start = Instant::now();
        trace!(
            "Starting stream task for downloading file `{}` from mirror {} with length {content_length:?} for client {}...",
            file_path.display(),
            conn_details.mirror,
            conn_details.client.ip().to_canonical()
        );

        let mut finished = false;
        let mut bytes = 0;
        let buf_size = global_config().buffer_size;

        let mut reader = tokio::io::BufReader::with_capacity(buf_size, &mut file);

        loop {
            loop {
                let mut buf = bytes::BytesMut::with_capacity(buf_size);
                let ret = match reader.read_buf(&mut buf).await {
                    Ok(r) if r > 0 => r,
                    Ok(_) => break,
                    Err(err) => {
                        error!("Error reading from file `{}`:  {err}", file_path.display());
                        return;
                    }
                };

                let buf = buf.freeze();

                bytes += ret as u64;
                assert_eq!(buf.len(), ret);

                if let Err(_err) = tx.send(Ok(buf)).await {
                    info!("Receiver of stream task closed; cancelling stream...");
                    return;
                }
            }

            if finished {
                break;
            }

            if let Err(_err) = receiver.changed().await {
                /* sender closed, either download finished or aborted */
                let st = status.read().await;
                match *st {
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
                }
            }
        }

        /* Perform cleanup before database operation */
        drop(reader);
        drop(receiver);
        drop(status);
        drop(tx);

        let elapsed = start.elapsed();
        info!(
            "Served new file {} from mirror {} for client {} in {} (size={}, rate={})",
            conn_details.debname,
            conn_details.mirror,
            conn_details.client.ip().to_canonical(),
            HumanFmt::Time(elapsed),
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
        .header(CONNECTION, HeaderValue::from_static("keep-alive"))
        .header(
            CONTENT_TYPE,
            HeaderValue::from_static("application/vnd.debian.binary-package"),
        )
        .header(ACCEPT_RANGES, HeaderValue::from_static("bytes"))
        .header(SERVER, HeaderValue::from_static(APP_NAME))
        .header(
            LAST_MODIFIED,
            HeaderValue::try_from(systemtime_to_http_datetime(create_time))
                .expect("Http datetime is valid"),
        );
    if let ContentLength::Exact(size) = content_length {
        let r = response_builder
            .headers_mut()
            .expect("request should be valid")
            .append(CONTENT_LENGTH, HeaderValue::from(size.get()));
        assert!(!r);
    }

    let channel_body = ChannelBody::new(rx, content_length);

    let response = match global_config().min_download_rate {
        Some(min_download_rate) => {
            let checked_channel_body = RateCheckedBody::new(
                channel_body.map_err(RateCheckedBodyErr::ProxyCache),
                min_download_rate,
            );
            response_builder
                .body(ProxyCacheBody::Boxed(BoxBody::new(
                    checked_channel_body.map_err(move |rerr| match rerr {
                        RateCheckedBodyErr::DownloadRate(download_rate_err) => {
                            ProxyCacheError::ClientDownloadRate(error::ClientDownloadRate {
                                download_rate_err,
                                client_ip: conn_details.client.ip(),
                            })
                        }
                        RateCheckedBodyErr::Hyper(herr) => ProxyCacheError::Hyper(herr),
                        RateCheckedBodyErr::ProxyCache(perr) => perr,
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

                return serve_cached_file(conn_details, req, database_tx, file, &path_clone).await;
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
                )
                .await;
            }
        }
    }
}

enum CacheFileStat<'a> {
    Volatile((tokio::fs::File, &'a Path, SystemTime)),
    NewVolatile,
    NewDefault,
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
    const KEEP_FINISHED_STATE_SECONDS: Duration = Duration::from_secs(30);

    let (volatile_file, warn_on_override, prev_file_size) = match &cfstate {
        CacheFileStat::Volatile((file, file_path, _local_modification_time)) => {
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

            (true, false, size)
        }
        CacheFileStat::NewVolatile => (true, true, 0),
        CacheFileStat::NewDefault => (false, true, 0),
    };

    let mut client_modified_since = None;
    let mut max_age = 300;

    for (name, value) in req.headers() {
        match name {
            &USER_AGENT | &RANGE | &IF_RANGE | &HOST | &ACCEPT => (),
            n if n == PROXY_CONNECTION => (),
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
            &IF_MODIFIED_SINCE => client_modified_since = Some(value),
            _ => warn_once_or_info!(
                "Unhandled HTTP header `{name}` with value `{value:?}` in request from client {}",
                conn_details.client.ip().to_canonical()
            ),
        }
    }

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

    let fwd_host = match req.headers().get(HOST) {
        Some(h) => h,
        None => &HeaderValue::from_str(&conn_details.mirror.host)
            .expect("connection host should be valid"),
    };

    let mut req_uri = std::borrow::Cow::Borrowed(req.uri());

    let mut fwd_request = Request::builder()
        .method(Method::GET)
        .uri(&*req_uri)
        .header(USER_AGENT, HeaderValue::from_static(APP_USER_AGENT))
        .header(HOST, fwd_host)
        .body(Empty::new())
        .expect("request should be valid");

    if let CacheFileStat::Volatile((_file, _file_path, local_modification_time)) = &cfstate {
        let date_fmt = systemtime_to_http_datetime(*local_modification_time);

        let r = fwd_request.headers_mut().append(
            IF_MODIFIED_SINCE,
            HeaderValue::try_from(date_fmt).expect("HTTP datetime should be valid"),
        );
        assert!(!r);

        let r = fwd_request.headers_mut().append(
            CACHE_CONTROL,
            HeaderValue::try_from(format!("max-age={max_age}")).expect("string is valid"),
        );
        assert!(!r);
    }

    trace!("Forwarded request: {fwd_request:?}");

    let mut fwd_response = match request_with_retry(&appstate.https_client, fwd_request).await {
        Ok(r) => r,
        Err(err) => {
            warn!(
                "Proxy request failed to mirror {}:  {err}",
                conn_details.mirror
            );
            *status.write().await =
                ActiveDownloadStatus::Aborted(AbortReason::AlreadyLoggedJustFail);
            appstate
                .active_downloads
                .remove(&conn_details.mirror, &conn_details.debname);
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

        if let Some(moved_host) = moved_uri.host()
            && is_host_allowed(moved_host)
        {
            let mut redirected_request = Request::builder()
                .method(Method::GET)
                .uri(&moved_uri)
                .header(USER_AGENT, HeaderValue::from_static(APP_USER_AGENT))
                .header(HOST, moved_host)
                .body(Empty::new())
                .expect("request should be valid");
            req_uri = std::borrow::Cow::Owned(moved_uri);

            if let CacheFileStat::Volatile((_file, _file_path, local_modification_time)) = &cfstate
            {
                let date_fmt = systemtime_to_http_datetime(*local_modification_time);

                let r = redirected_request.headers_mut().append(
                    IF_MODIFIED_SINCE,
                    HeaderValue::try_from(date_fmt).expect("HTTP datetime should be valid"),
                );
                assert!(!r);

                let r = redirected_request.headers_mut().append(
                    CACHE_CONTROL,
                    HeaderValue::try_from(format!("max-age={max_age}")).expect("string is valid"),
                );
                assert!(!r);
            }

            trace!("Forwarded redirected request: {redirected_request:?}");

            let redirected_response =
                match request_with_retry(&appstate.https_client, redirected_request).await {
                    Ok(r) => r,
                    Err(err) => {
                        warn!("Proxy redirected request to host {fwd_host:?} failed:  {err}");
                        *status.write().await =
                            ActiveDownloadStatus::Aborted(AbortReason::AlreadyLoggedJustFail);
                        appstate
                            .active_downloads
                            .remove(&conn_details.mirror, &conn_details.debname);
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

    if let CacheFileStat::Volatile((file, file_path, local_modification_time)) = cfstate {
        if fwd_response.status() == StatusCode::NOT_MODIFIED {
            *status.write().await = ActiveDownloadStatus::Finished(file_path.to_path_buf());
            // ignore if there are no receivers
            init_tx.send_replace(());

            let mirror_clone = conn_details.mirror.clone();
            let debname_clone = conn_details.debname.clone();
            tokio::task::spawn(async move {
                // Keep ActiveDownloadStatus::Finished of volatile files in the hashmap for a short
                // time to avoid unnecessary "IF_MODIFIED_SINCE" recheck requests to the mirror.
                tokio::time::sleep(KEEP_FINISHED_STATE_SECONDS).await;
                appstate
                    .active_downloads
                    .remove(&mirror_clone, &debname_clone);
            });

            let Some(client_modified_since) = client_modified_since else {
                // If the client is not checking the modification timestamp, send the whole file
                return serve_cached_file(conn_details, req, appstate.database_tx, file, file_path)
                    .await;
            };

            if let Some(response) =
                not_modified_response(client_modified_since, local_modification_time)
            {
                // If the client-file is up to date, send a NOT_MODIFIED (304) response
                info!(
                    "Serving info about up-to-date cached file {} from mirror {} for client {}",
                    conn_details.debname,
                    conn_details.mirror,
                    conn_details.client.ip().to_canonical()
                );

                return response;
            }

            // If the client-file is outdated, send the whole file
            info!(
                "File {} from mirror {} is up-to-date in cache, serving to client {} with older version",
                conn_details.debname,
                conn_details.mirror,
                conn_details.client.ip().to_canonical()
            );

            return serve_cached_file(conn_details, req, appstate.database_tx, file, file_path)
                .await;
        }

        debug!(
            "File `{}` is outdated (status={}), downloading new version",
            file_path.display(),
            fwd_response.status()
        );
    }

    if fwd_response.status() != StatusCode::OK {
        warn!(
            "Request for file {} from mirror {} with URI `{req_uri}` failed with code `{}`, got response: {fwd_response:?}",
            conn_details.debname,
            conn_details.mirror,
            fwd_response.status()
        );
        *status.write().await = ActiveDownloadStatus::Aborted(AbortReason::AlreadyLoggedJustFail);
        appstate
            .active_downloads
            .remove(&conn_details.mirror, &conn_details.debname);

        let (parts, body) = fwd_response.into_parts();

        let body = ProxyCacheBody::Boxed(BoxBody::new(body.map_err(ProxyCacheError::Hyper)));

        let response = Response::from_parts(parts, body);

        trace!("Outgoing response: {response:?}");

        return response;
    }

    let content_length = match fwd_response.headers().get(CONTENT_LENGTH).and_then(|hv| {
        hv.to_str()
            .ok()
            .and_then(|ct| ct.parse::<NonZero<u64>>().ok())
    }) {
        Some(size) => ContentLength::Exact(size),
        None if volatile_file => ContentLength::Unknown(VOLATILE_UNKNOWN_CONTENT_LENGTH_UPPER),
        None => {
            warn!(
                "Could not extract content-length from header for file {} from mirror {}: {fwd_response:?}",
                conn_details.debname, conn_details.mirror
            );
            *status.write().await =
                ActiveDownloadStatus::Aborted(AbortReason::AlreadyLoggedJustFail);
            appstate
                .active_downloads
                .remove(&conn_details.mirror, &conn_details.debname);
            return quick_response(
                StatusCode::BAD_GATEWAY,
                "Upstream resource has no content length",
            );
        }
    };

    if let Some(quota) = global_config().disk_quota {
        let fail = {
            let mut mg_cache_size = RUNTIMEDETAILS
                .get()
                .expect("global is set in main()")
                .cache_size
                .lock();
            let mut csize = *mg_cache_size;
            let quota_reached = content_length
                .upper()
                .checked_add(csize)
                .is_none_or(|sum| sum > quota);

            if quota_reached {
                drop(mg_cache_size);
                warn!(
                    "Disk quota reached: file={} cache_size={} content_length={:?} quota={}",
                    conn_details.debname, csize, content_length, quota
                );

                true
            } else {
                trace!(
                    "Adjusting cache size for file {} to be downloaded by {} minus previous file size {prev_file_size}",
                    conn_details.debname,
                    content_length.upper().get()
                );

                csize = csize
                    .checked_add(content_length.upper().get())
                    .expect("should not overflow by previous check");
                match csize.checked_sub(prev_file_size) {
                    Some(val) => csize = val,
                    None => {
                        error!(
                            "Cache size corruption: current={csize} previous_file_size={prev_file_size}"
                        );
                    }
                }
                *mg_cache_size = csize;

                false
            }
        };

        if fail {
            *status.write().await =
                ActiveDownloadStatus::Aborted(AbortReason::AlreadyLoggedJustFail);
            appstate
                .active_downloads
                .remove(&conn_details.mirror, &conn_details.debname);
            return quick_response(StatusCode::SERVICE_UNAVAILABLE, "Disk quota reached");
        }
    }

    let (_parts, body) = fwd_response.into_parts();

    let tmppath: PathBuf = [
        &global_config().cache_directory,
        Path::new("tmp"),
        Path::new(&conn_details.debname),
    ]
    .iter()
    .collect();

    let (outfile, outpath) = match tokio_mkstemp(&tmppath, 0o640).await {
        Ok((f, p)) => (f, p),
        Err(err) => {
            error!(
                "Error creating temporary file `{}`:  {err}",
                tmppath.display()
            );

            {
                trace!(
                    "Adjusting cache size for file {} failed to be downloaded by {} plus previous file size {prev_file_size}",
                    conn_details.debname,
                    content_length.upper().get()
                );

                let mut mg_cache_size = RUNTIMEDETAILS
                    .get()
                    .expect("global is set in main()")
                    .cache_size
                    .lock();
                let mut csize = *mg_cache_size;
                csize = csize.saturating_sub(content_length.upper().get());
                csize = csize
                    .checked_add(prev_file_size)
                    .expect("size should not overflow");
                *mg_cache_size = csize;
            }

            *status.write().await =
                ActiveDownloadStatus::Aborted(AbortReason::AlreadyLoggedJustFail);
            appstate
                .active_downloads
                .remove(&conn_details.mirror, &conn_details.debname);
            return quick_response(StatusCode::INTERNAL_SERVER_ERROR, "Cache Access Failure");
        }
    };

    info!(
        "Downloading and serving new file {} from mirror {} for client {}...",
        conn_details.debname,
        conn_details.mirror,
        conn_details.client.ip().to_canonical()
    );

    let (tx, rx) = tokio::sync::watch::channel(());

    *status.write().await = ActiveDownloadStatus::Download(outpath.clone(), content_length, rx);
    // ignore if there are no receivers
    init_tx.send_replace(());

    let cd = conn_details.clone();
    let st = Arc::clone(&status);
    let db_tx = appstate.database_tx.clone();
    let curr_downloads = appstate.active_downloads.download_count();
    tokio::task::spawn(async move {
        let mut delay_finished_state_removal = cd.volatile;

        download_file(
            db_tx,
            &cd,
            warn_on_override,
            &st,
            (body, content_length),
            (outfile, outpath),
            tx,
        )
        .await;

        {
            let ads = st.read().await;
            assert!(!matches!(*ads, ActiveDownloadStatus::Init(_)));
            if !matches!(*(ads), ActiveDownloadStatus::Finished(_)) {
                trace!(
                    "Adjusting cache size for file {} not finished downloading by {} plus previous file size {prev_file_size}",
                    cd.debname,
                    content_length.upper().get()
                );

                delay_finished_state_removal = false;

                let mut mg_cache_size = RUNTIMEDETAILS
                    .get()
                    .expect("global is set in main()")
                    .cache_size
                    .lock();
                let mut csize = *mg_cache_size;
                csize = csize.saturating_sub(content_length.upper().get());
                csize = csize
                    .checked_add(prev_file_size)
                    .expect("size should not overflow");
                *mg_cache_size = csize;
            }
        }

        if delay_finished_state_removal {
            // Keep ActiveDownloadStatus::Finished of volatile files in the hashmap for a short
            // time to avoid unnecessary "IF_MODIFIED_SINCE" recheck requests to the mirror.
            tokio::time::sleep(KEEP_FINISHED_STATE_SECONDS).await;
        }
        appstate.active_downloads.remove(&cd.mirror, &cd.debname);
    });

    let gcfg = global_config();

    if !volatile_file
        && gcfg.experimental_parallel_hack_enabled
        && gcfg
            .experimental_parallel_hack_maxparallel
            .is_none_or(|max_parallel| curr_downloads <= max_parallel.get())
        && gcfg
            .experimental_parallel_hack_minsize
            .is_none_or(|size| content_length.upper() > size)
    {
        #[expect(clippy::cast_precision_loss)]
        let p = (curr_downloads.saturating_sub(1) as f64)
            .mul_add(-gcfg.experimental_parallel_hack_factor, 1.0)
            .max(0.0);
        let d = Bernoulli::new(p).expect("p is valid");
        let v = d.sample(&mut rand::rng());

        if v {
            debug!(
                "Trying parallel download hack for client {} and file {} with code {} and retry after value {}",
                conn_details.client.ip().to_canonical(),
                conn_details.debname,
                gcfg.experimental_parallel_hack_statuscode,
                gcfg.experimental_parallel_hack_retryafter
            );

            let mut response = Response::builder()
                .status(gcfg.experimental_parallel_hack_statuscode)
                .header(SERVER, HeaderValue::from_static(APP_NAME))
                .body(ProxyCacheBody::Empty(Empty::new()))
                .expect("Response is valid");

            if gcfg.experimental_parallel_hack_retryafter != 0 {
                response.headers_mut().append(
                    RETRY_AFTER,
                    HeaderValue::from(gcfg.experimental_parallel_hack_retryafter),
                );
            }

            trace!("Outgoing parallel download hack response: {response:?}");

            return response;
        }
    }

    serve_downloading_file(conn_details, req, appstate.database_tx, status).await
}

/// Create a TCP connection to host:port, build a tunnel between the connection and
/// the upgraded connection
async fn tunnel(
    client: SocketAddr,
    upgraded: hyper::upgrade::Upgraded,
    host: &str,
    port: NonZero<u16>,
) -> std::io::Result<()> {
    let start = Instant::now();

    /* Connect to remote server */
    let mut server = tokio::net::TcpStream::connect((host, port.get())).await?;
    let mut upgraded = TokioIo::new(upgraded);

    /* Proxying data */
    let bufsize = global_config().buffer_size;
    let (from_client, from_server) =
        tokio::io::copy_bidirectional_with_sizes(&mut upgraded, &mut server, bufsize, bufsize)
            .await?;

    info!(
        "Tunneled client {} wrote {} and received {} from {host}:{port} in {}",
        client.ip().to_canonical(),
        HumanFmt::Size(from_client),
        HumanFmt::Size(from_server),
        HumanFmt::Time(start.elapsed())
    );

    Ok(())
}

#[must_use]
pub(crate) async fn process_cache_request(
    conn_details: ConnectionDetails,
    req: Request<Empty<()>>,
    appstate: AppState,
) -> Response<ProxyCacheBody> {
    let cache_path: PathBuf = [
        &global_config().cache_directory,
        Path::new(
            &conn_details
                .aliased_host
                .unwrap_or(&conn_details.mirror.host),
        ),
        Path::new(&conn_details.mirror.path),
        conn_details.subdir.unwrap_or_else(|| Path::new("")),
        Path::new(&conn_details.debname),
    ]
    .iter()
    .collect();

    match tokio::fs::File::open(&cache_path).await {
        Ok(file) => {
            trace!(
                "File {} found, serving {} version...",
                cache_path.display(),
                if conn_details.volatile {
                    "volatile"
                } else {
                    "cached"
                }
            );
            if conn_details.volatile {
                serve_volatile_file(conn_details, req, file, &cache_path, appstate).await
            } else {
                serve_cached_file(conn_details, req, appstate.database_tx, file, &cache_path).await
            }
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            let (init_tx, status) = appstate
                .active_downloads
                .insert(conn_details.mirror.clone(), conn_details.debname.clone());

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
                let cfstate = if conn_details.volatile {
                    CacheFileStat::NewVolatile
                } else {
                    CacheFileStat::NewDefault
                };

                serve_new_file(conn_details, status, init_tx, req, cfstate, appstate).await
            } else {
                info!(
                    "Serving file {} already in download from mirror {} for client {}...",
                    conn_details.debname,
                    conn_details.mirror,
                    conn_details.client.ip().to_canonical()
                );
                serve_downloading_file(conn_details, req, appstate.database_tx, status).await
            }
        }
        Err(err) => {
            error!("Error opening file `{}`:  {err}", cache_path.display());
            quick_response(
                hyper::StatusCode::INTERNAL_SERVER_ERROR,
                "Cache Access Failure",
            )
        }
    }
}

#[must_use]
fn connect_response(
    client: SocketAddr,
    req: Request<hyper::body::Incoming>,
) -> Response<ProxyCacheBody> {
    let cfg = global_config();

    if !cfg.https_tunnel_enabled {
        info!(
            "Rejecting https tunnel request for client {}",
            client.ip().to_canonical()
        );
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
        warn_once_or_info!("Invalid CONNECT address: {}", req.uri());
        return quick_response(StatusCode::BAD_REQUEST, "Invalid CONNECT address");
    };

    if !cfg.https_tunnel_allowed_ports.is_empty()
        && cfg.https_tunnel_allowed_ports.binary_search(&port).is_err()
    {
        info!(
            "Rejecting https tunnel request for client {} to not permitted port {}",
            client.ip().to_canonical(),
            port
        );
        return quick_response(StatusCode::FORBIDDEN, "HTTPS tunneling disabled");
    }

    if !cfg.https_tunnel_allowed_mirrors.is_empty()
        && cfg
            .https_tunnel_allowed_mirrors
            .binary_search(&host)
            .is_err()
    {
        info!(
            "Rejecting https tunnel request for client {} due to not permitted host {}",
            client.ip().to_canonical(),
            host
        );
        return quick_response(StatusCode::FORBIDDEN, "HTTPS tunneling disabled");
    }

    info!(
        "Using un-cached tunnel for client {} to {host}:{port}",
        client.ip().to_canonical()
    );

    tokio::task::spawn(async move {
        match hyper::upgrade::on(req).await {
            Ok(upgraded) => {
                if let Err(err) = tunnel(client, upgraded, &host, port).await {
                    if err.kind() == ErrorKind::NotConnected {
                        info!(
                            "Error tunneling connection for client {} to {host}:{port}:  {err}",
                            client.ip().to_canonical()
                        );
                    } else if err.kind() == ErrorKind::ConnectionReset {
                        warn!(
                            "Error tunneling connection for client {} to {host}:{port}:  {err}",
                            client.ip().to_canonical()
                        );
                    } else {
                        error!(
                            "Error tunneling connection for client {} to {host}:{port}:  {err}",
                            client.ip().to_canonical()
                        );
                    }
                }
            }
            Err(err) => error!(
                "Error upgrading connection for client {} to {host}:{port}:  {err}",
                client.ip().to_canonical()
            ),
        }
    });

    Response::new(ProxyCacheBody::Empty(Empty::new()))
}

#[inline]
async fn pre_process_client_request_wrapper(
    client: SocketAddr,
    req: Request<hyper::body::Incoming>,
    appstate: AppState,
) -> Result<Response<ProxyCacheBody>, Infallible> {
    Ok(pre_process_client_request(client, req, appstate).await)
}

#[must_use]
async fn pre_process_client_request(
    client: SocketAddr,
    req: Request<hyper::body::Incoming>,
    appstate: AppState,
) -> Response<ProxyCacheBody> {
    trace!("Incoming request: {req:?}");

    let gc = global_config();

    if Method::CONNECT == req.method() {
        {
            let allowed_proxy_clients = gc.allowed_proxy_clients.as_slice();
            if !allowed_proxy_clients.is_empty()
                && !allowed_proxy_clients
                    .iter()
                    .any(|ac| ac.contains(&client.ip().to_canonical()))
            {
                warn_once_or_info!("Unauthorized proxy client {}", client.ip().to_canonical());
                return quick_response(hyper::StatusCode::FORBIDDEN, "Unauthorized client");
            }
        }

        return connect_response(client, req);
    }

    if Method::GET != req.method() {
        warn_once_or_info!("Unsupported request method {}", req.method());
        return quick_response(hyper::StatusCode::BAD_REQUEST, "Method not supported");
    }

    let requested_host =
        if let Some(h) = req.uri().authority().map(hyper::http::uri::Authority::host) {
            h.to_owned()
        } else {
            {
                let allowed_webif_clients = gc
                    .allowed_webif_clients
                    .as_ref()
                    .unwrap_or(&gc.allowed_proxy_clients);
                if !allowed_webif_clients.is_empty()
                    && !allowed_webif_clients
                        .iter()
                        .any(|ac| ac.contains(&client.ip().to_canonical()))
                {
                    warn_once_or_info!(
                        "Unauthorized web-interface client {}",
                        client.ip().to_canonical()
                    );
                    return quick_response(hyper::StatusCode::FORBIDDEN, "Unauthorized client");
                }
            }

            return serve_web_interface(req, &appstate).await;
        };

    {
        let allowed_proxy_clients = gc.allowed_proxy_clients.as_slice();
        if !allowed_proxy_clients.is_empty()
            && !allowed_proxy_clients
                .iter()
                .any(|ac| ac.contains(&client.ip().to_canonical()))
        {
            warn_once_or_info!("Unauthorized proxy client {}", client.ip().to_canonical());
            return quick_response(hyper::StatusCode::FORBIDDEN, "Unauthorized client");
        }
    }

    let requested_host = match DomainName::new(requested_host) {
        Ok(d) => d,
        Err(rh) => {
            warn_once_or_info!("Unsupported host {rh}");
            return quick_response(hyper::StatusCode::BAD_REQUEST, "Unsupported host");
        }
    };

    if !is_host_allowed(&requested_host) {
        warn_once_or_info!("Unauthorized host {requested_host}");
        return quick_response(hyper::StatusCode::BAD_REQUEST, "Unauthorized host");
    }

    let aliased_host = gc
        .aliases
        .iter()
        .find(|alias| alias.aliases.binary_search(&requested_host).is_ok())
        .map(|alias| &alias.main);

    if req.body().size_hint().exact() != Some(0) {
        warn_once_or_info!("Request has non empty body, not forwarding body: {req:?}");
    }
    let (parts, _body) = req.into_parts();
    let req = Request::from_parts(parts, Empty::new());

    let requested_path = req.uri().path();

    trace!(
        "Requested host: `{requested_host}`; Aliased host: `{aliased_host:?}`; Requested path: `{requested_path}`"
    );

    if let Some(resource) = parse_request_path(requested_path) {
        match resource {
            ResourceFile::Pool(mirror_path, filename) => {
                // TODO: cache .dsc?
                #[expect(clippy::case_sensitive_file_extension_comparisons)]
                let is_deb = filename.ends_with(".deb");

                if is_deb {
                    // TODO: refactor decoding
                    let mirrorname = match urlencoding::decode(mirror_path) {
                        Ok(s) => s,
                        Err(err) => {
                            error!("Error decoding mirror path `{mirror_path}`:  {err}");
                            return quick_response(
                                StatusCode::BAD_REQUEST,
                                "Unsupported URL encoding",
                            );
                        }
                    };
                    if !valid_mirrorname(&mirrorname) {
                        warn_once_or_info!("Unsupported mirror name `{mirrorname}`");
                        return quick_response(
                            hyper::StatusCode::BAD_REQUEST,
                            "Unsupported mirror name",
                        );
                    }

                    let debname = match urlencoding::decode(filename) {
                        Ok(s) => s,
                        Err(err) => {
                            error!("Error decoding filename `{filename}`:  {err}");
                            return quick_response(
                                StatusCode::BAD_REQUEST,
                                "Unsupported URL encoding",
                            );
                        }
                    };
                    if !valid_filename(&debname) {
                        warn_once_or_info!("Unsupported file name `{debname}`");
                        return quick_response(
                            hyper::StatusCode::BAD_REQUEST,
                            "Unsupported file name",
                        );
                    }

                    trace!("Decoded mirrorname: `{mirrorname}`; Decoded debname: `{debname}`");

                    let conn_details = ConnectionDetails {
                        client,
                        mirror: Mirror {
                            host: requested_host,
                            path: mirrorname.into_owned(),
                        },
                        aliased_host,
                        debname: debname.into_owned(),
                        subdir: None,
                        volatile: false,
                    };

                    return process_cache_request(conn_details, req, appstate).await;
                }

                warn_once_or_info!("Unsupported pool file extension in filename `{filename}`");
            }
            ResourceFile::Dists(mirror_path, distribution, filename) => {
                let mirrorname = match urlencoding::decode(mirror_path) {
                    Ok(s) => s,
                    Err(err) => {
                        error!("Error decoding mirror path `{mirror_path}`:  {err}");
                        return quick_response(StatusCode::BAD_REQUEST, "Unsupported URL encoding");
                    }
                };
                if !valid_mirrorname(&mirrorname) {
                    warn_once_or_info!("Unsupported mirror name `{mirrorname}`");
                    return quick_response(
                        hyper::StatusCode::BAD_REQUEST,
                        "Unsupported mirror name",
                    );
                }

                let distribution = match urlencoding::decode(distribution) {
                    Ok(s) => s,
                    Err(err) => {
                        error!("Error decoding distribution `{distribution}`:  {err}");
                        return quick_response(StatusCode::BAD_REQUEST, "Unsupported URL encoding");
                    }
                };
                if !valid_distribution(&distribution) {
                    warn_once_or_info!("Unsupported distribution name `{distribution}`");
                    return quick_response(
                        hyper::StatusCode::BAD_REQUEST,
                        "Unsupported distribution name",
                    );
                }

                let filename = match urlencoding::decode(filename) {
                    Ok(s) => s,
                    Err(err) => {
                        error!("Error decoding filename `{filename}`:  {err}");
                        return quick_response(StatusCode::BAD_REQUEST, "Unsupported URL encoding");
                    }
                };
                if !valid_filename(&filename) {
                    warn_once_or_info!("Unsupported file name `{filename}`");
                    return quick_response(hyper::StatusCode::BAD_REQUEST, "Unsupported file name");
                }

                trace!(
                    "Decoded mirrorname: `{mirrorname}`; Decoded distribution: `{distribution}`; Decoded filename: `{filename}`"
                );

                let conn_details = ConnectionDetails {
                    client,
                    mirror: Mirror {
                        host: requested_host,
                        path: mirrorname.into_owned(),
                    },
                    aliased_host,
                    debname: format!("{distribution}_{filename}"),
                    subdir: Some(Path::new("dists")),
                    volatile: true,
                };

                return process_cache_request(conn_details, req, appstate).await;
            }
            ResourceFile::ByHash(mirror_path, filename) => {
                let mirrorname = match urlencoding::decode(mirror_path) {
                    Ok(s) => s,
                    Err(err) => {
                        error!("Error decoding mirror path `{mirror_path}`:  {err}");
                        return quick_response(StatusCode::BAD_REQUEST, "Unsupported URL encoding");
                    }
                };
                if !valid_mirrorname(&mirrorname) {
                    warn_once_or_info!("Unsupported mirror name `{mirrorname}`");
                    return quick_response(
                        hyper::StatusCode::BAD_REQUEST,
                        "Unsupported mirror name",
                    );
                }

                let filename = match urlencoding::decode(filename) {
                    Ok(s) => s,
                    Err(err) => {
                        error!("Error decoding filename `{filename}`:  {err}");
                        return quick_response(StatusCode::BAD_REQUEST, "Unsupported URL encoding");
                    }
                };
                if !valid_filename(&filename) {
                    warn_once_or_info!("Unsupported file name `{filename}`");
                    return quick_response(hyper::StatusCode::BAD_REQUEST, "Unsupported file name");
                }

                trace!("Decoded mirrorname: `{mirrorname}`; Decoded filename: `{filename}`");

                let conn_details = ConnectionDetails {
                    client,
                    mirror: Mirror {
                        host: requested_host,
                        path: mirrorname.into_owned(),
                    },
                    aliased_host,
                    debname: filename.to_string(),
                    subdir: Some(Path::new("dists/by-hash")),
                    volatile: false,
                };

                // files requested by hash shouldn't be volatile
                return process_cache_request(conn_details, req, appstate).await;
            }
            ResourceFile::Package(mirror_path, distribution, component, architecture, filename) => {
                let mirrorname = match urlencoding::decode(mirror_path) {
                    Ok(s) => s,
                    Err(err) => {
                        error!("Error decoding mirror path `{mirror_path}`:  {err}");
                        return quick_response(StatusCode::BAD_REQUEST, "Unsupported URL encoding");
                    }
                };
                if !valid_mirrorname(&mirrorname) {
                    warn_once_or_info!("Unsupported mirror name `{mirrorname}`");
                    return quick_response(
                        hyper::StatusCode::BAD_REQUEST,
                        "Unsupported mirror name",
                    );
                }

                let distribution = match urlencoding::decode(distribution) {
                    Ok(s) => s,
                    Err(err) => {
                        error!("Error decoding distribution `{distribution}`:  {err}");
                        return quick_response(StatusCode::BAD_REQUEST, "Unsupported URL encoding");
                    }
                };
                if !valid_distribution(&distribution) {
                    warn_once_or_info!("Unsupported distribution name `{distribution}`");
                    return quick_response(
                        hyper::StatusCode::BAD_REQUEST,
                        "Unsupported distribution name",
                    );
                }

                let component = match urlencoding::decode(component) {
                    Ok(s) => s,
                    Err(err) => {
                        error!("Error decoding component `{component}`:  {err}");
                        return quick_response(StatusCode::BAD_REQUEST, "Unsupported URL encoding");
                    }
                };
                if !valid_component(&component) {
                    warn!("Unsupported component name `{component}`");
                    return quick_response(
                        hyper::StatusCode::BAD_REQUEST,
                        "Unsupported component name",
                    );
                }

                let architecture = match urlencoding::decode(architecture) {
                    Ok(s) => s,
                    Err(err) => {
                        error!("Error decoding architecture `{architecture}`:  {err}");
                        return quick_response(StatusCode::BAD_REQUEST, "Unsupported URL encoding");
                    }
                };
                if !valid_architecture(&architecture) {
                    warn_once_or_info!("Unsupported architecture name `{architecture}`");
                    return quick_response(
                        hyper::StatusCode::BAD_REQUEST,
                        "Unsupported architecture name",
                    );
                }

                let filename = match urlencoding::decode(filename) {
                    Ok(s) => s,
                    Err(err) => {
                        error!("Error decoding filename `{filename}`:  {err}");
                        return quick_response(StatusCode::BAD_REQUEST, "Unsupported URL encoding");
                    }
                };
                if !valid_filename(&filename) {
                    warn_once_or_info!("Unsupported file name `{filename}`");
                    return quick_response(hyper::StatusCode::BAD_REQUEST, "Unsupported file name");
                }

                trace!(
                    "Decoded mirrorname: `{mirrorname}`; Decoded distribution: `{distribution}`; Decoded component: `{component}`; Decoded architecture: `{architecture}`; Decoded filename: `{filename}`"
                );

                let conn_details = ConnectionDetails {
                    client,
                    mirror: Mirror {
                        host: requested_host,
                        path: mirrorname.into_owned(),
                    },
                    aliased_host,
                    debname: format!("{distribution}_{component}_{architecture}_{filename}"),
                    subdir: Some(Path::new("dists")),
                    volatile: true,
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
    #[expect(clippy::items_after_statements)]
    fn ignore_uncached_path(uri_path: &str) -> bool {
        uri_path.contains("/Packages.diff/T-")
            || uri_path.contains("/Translation-en.diff/T-")
            || uri_path.contains("/Sources.diff/T-")
    }

    if ignore_uncached_path(requested_path) {
        info!("Proxying (without caching) request {}", req.uri());
    } else {
        warn_once_or_info!("Proxying (without caching) request {}", req.uri());

        let mut uncacheables = UNCACHEABLES.get().expect("Initialized in main()").write();

        // always delete to keep recent entries fresh
        if let Some((idx, (_h, _p))) = uncacheables
            .iter()
            .enumerate()
            .find(|(_idx, (h, p))| *h == requested_host && *p == requested_path)
        {
            let entry = uncacheables.remove(idx).expect("entry exists");
            debug_assert_eq!(entry.0, requested_host);
            debug_assert_eq!(entry.1, requested_path);

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
            warn!("Proxy request to host {requested_host} failed:  {err}");
            return quick_response(StatusCode::SERVICE_UNAVAILABLE, "Proxy request failed");
        }
    };

    trace!("Forwarded response: {fwd_response:?}");

    if (fwd_response.status().is_success() || fwd_response.status().is_redirection())
        && let Some(origin) = Origin::from_path(parts_cloned.uri.path(), requested_host.clone())
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

        if moved_uri.host().is_some_and(is_host_allowed) {
            parts_cloned.uri = moved_uri;
            let redirected_request = Request::from_parts(parts_cloned, Empty::new());

            trace!("Redirected request: {redirected_request:?}");

            let redirected_response =
                match request_with_retry(&appstate.https_client, redirected_request).await {
                    Ok(r) => r,
                    Err(err) => {
                        warn!("Redirected proxy request to host {requested_host} failed:  {err}");
                        return quick_response(
                            StatusCode::SERVICE_UNAVAILABLE,
                            "Proxy request failed",
                        );
                    }
                };

            trace!("Redirected response: {redirected_response:?}");

            let (parts, body) = redirected_response.into_parts();

            let body = ProxyCacheBody::Boxed(BoxBody::new(body.map_err(ProxyCacheError::Hyper)));

            let response = Response::from_parts(parts, body);

            trace!("Outgoing response: {response:?}");

            return response;
        }
    }

    let response = fwd_response
        .map(|body| ProxyCacheBody::Boxed(BoxBody::new(body.map_err(ProxyCacheError::Hyper))));

    trace!("Outgoing response: {response:?}");

    response
}

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
fn is_timeout(err: &hyper::Error) -> bool {
    err.source().is_some_and(|source_err| {
        source_err
            .downcast_ref::<ProxyCacheError>()
            .is_some_and(|pe| {
                matches!(pe, ProxyCacheError::ClientDownloadRate(_))
                    || matches!(pe, ProxyCacheError::MirrorDownloadRate(_))
            })
    })
}

async fn main_loop() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    #[cfg(feature = "tokio_console")]
    console_subscriber::init();
    #[cfg(feature = "tokio_console")]
    warn!("Using console_subscriber for tokio-console...");

    let config = global_config();

    let mut addr = SocketAddr::from((config.bind_addr, config.bind_port.get()));

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
    info!("Listening on http://{addr}");

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

    let (db_task_tx, db_task_rx) = tokio::sync::mpsc::channel(64);
    {
        let database = database.clone();
        tokio::spawn(db_loop(database, db_task_rx));
    }

    {
        let database = database.clone();
        tokio::task::spawn(async move {
            if let Ok(cache_size) = task_cache_scan(&database).await {
                let rd = RUNTIMEDETAILS.get().expect("global set in main()");

                {
                    *rd.cache_size.lock() = cache_size;
                }

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

    let active_downloads = ActiveDownloads::new();

    let mut term_signal = tokio::signal::unix::signal(SignalKind::terminate())?;
    let mut usr1_signal = tokio::signal::unix::signal(SignalKind::user_defined1())?;

    let first_cleanup = tokio::time::Instant::now() + Duration::from_secs(60 * 60); /* 1h */
    let mut cleanup_interval =
        tokio::time::interval_at(first_cleanup, Duration::from_secs(24 * 60 * 60)); /* every 24h */

    let appstate = AppState {
        database,
        database_tx: db_task_tx,
        https_client,
        active_downloads,
    };

    loop {
        trace!(
            "Active downloads ({}):  {:?}",
            appstate.active_downloads.len(),
            appstate.active_downloads
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

        let (stream, client) = next.map_err(|err| {
            error!("Error accepting connection:  {err}");
            err
        })?;

        info!("New client connection from {}", client.ip().to_canonical());
        let client_start = Instant::now();

        let appstate = appstate.clone();
        tokio::task::spawn(async move {
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
                    info!(
                        "Connection to client {} cancelled",
                        client.ip().to_canonical()
                    );
                } else if is_shutdown_disconnect(&err) {
                    info!(
                        "Improper connection shutdown for client {}:  {err}",
                        client.ip().to_canonical()
                    );
                } else if is_broken_pipe(&err) {
                    info!(
                        "Broken pipe for client {}:  {err}",
                        client.ip().to_canonical()
                    );
                } else if is_timeout(&err) {
                    let perr = err
                        .source()
                        .expect("Error has source")
                        .downcast_ref::<ProxyCacheError>()
                        .expect("Error is Proxyerror");
                    info!("{perr}");
                } else {
                    error!(
                        "Error serving connection for client {}:  {err} -- {err:?}",
                        client.ip().to_canonical()
                    );
                    let mut lerr: &dyn Error = &err;
                    loop {
                        lerr = match lerr.source() {
                            Some(e) => e,
                            None => break,
                        };
                        error!(
                            "Error serving connection for client {}:  {lerr} -- {lerr:?}",
                            client.ip().to_canonical()
                        );
                    }
                }
            }

            info!(
                "Closed connection to {} after {}",
                client.ip().to_canonical(),
                HumanFmt::Time(client_start.elapsed())
            );
        });
    }
}

const fn get_long_version() -> &'static str {
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

    concat!(
        env!("CARGO_PKG_VERSION"),
        "\n",
        "TLS: ",
        feature_tls!(),
        "\n",
        "MMAP: ",
        feature_mmap!()
    )
}

#[derive(Parser)]
#[command(author, version, long_version(get_long_version()), about)]
struct Cli {
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
    cache_size: parking_lot::Mutex<u64>,
}

static RUNTIMEDETAILS: OnceLock<RuntimeDetails> = OnceLock::new();
static LOGSTORE: OnceLock<LogStore> = OnceLock::new();
static UNCACHEABLES: OnceLock<parking_lot::RwLock<RingBuffer<(DomainName, String)>>> =
    OnceLock::new();

#[must_use]
#[inline]
fn global_config() -> &'static Config {
    &RUNTIMEDETAILS
        .get()
        .expect("Global was initialized in main()")
        .config
}

#[expect(clippy::print_stderr)]
fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let args = Cli::parse();

    let (config, cgf_fallback) = Config::new(&args.config_path)?;

    let config_log_level = config.log_level;
    let config_logstore_capacity = config.logstore_capacity;

    RUNTIMEDETAILS
        .set(RuntimeDetails {
            start_time: time::OffsetDateTime::now_utc(),
            config,
            cache_size: parking_lot::Mutex::new(0),
        })
        .expect("Initial set in main() should succeed");

    let output_log_config = ConfigBuilder::new()
        .set_time_level(if args.skip_log_timestamp {
            LevelFilter::Off
        } else {
            LevelFilter::Error
        })
        .set_thread_level(if config_log_level >= LevelFilter::Debug {
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

    CombinedLogger::init(vec![
        TermLogger::new(
            args.log_level.unwrap_or(config_log_level),
            output_log_config,
            TerminalMode::Mixed,
            ColorChoice::Auto,
        ),
        WriteLogger::new(
            LevelFilter::Warn,
            internal_log_config,
            LOGSTORE.get().expect("Should be set").clone(),
        ),
    ])?;

    debug!("Logger initialized");
    trace!("Tracing enabled");

    if cgf_fallback {
        info!(
            "Default configuration file `{}` not found, using defaults",
            args.config_path.display()
        );
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

    runtime.block_on(async { main_loop().await })
}
