#![cfg_attr(
    test,
    allow(clippy::map_unwrap_or, clippy::unwrap_used, clippy::too_many_lines)
)]

mod config;
mod database;
mod deb_mirror;
mod error;
mod http_range;
mod humanfmt;
mod log_once;
mod logstore;
mod ringbuffer;
mod task_cache_scan;
mod task_cleanup;
mod task_setup;
mod web_interface;

use std::borrow::Borrow;
use std::borrow::Cow;
use std::collections::HashMap;
use std::error::Error;
use std::hash::Hash;
use std::hash::Hasher;
use std::io::ErrorKind;
use std::net::SocketAddr;
use std::num::NonZero;
use std::num::NonZeroU16;
use std::num::NonZeroU64;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::path::PathBuf;
use std::pin::pin;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::OnceLock;
use std::task::Poll::{Pending, Ready};
use std::time::Duration;
use std::time::Instant;
use std::time::SystemTime;

use clap::Parser;
use futures_util::TryStreamExt;
use http_body_util::{combinators::BoxBody, BodyExt, Empty, Full};
use hyper::body::Frame;
use hyper::body::Incoming;
use hyper::body::SizeHint;
use hyper::header::HeaderName;
use hyper::header::HeaderValue;
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
use hyper::{body::Body, Method, Request, Response, StatusCode};
use hyper_rustls::ConfigBuilderExt;
use hyper_rustls::HttpsConnector;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioIo;
use log::{debug, error, info, trace, warn, LevelFilter};
use pin_project::{pin_project, pinned_drop};
use rand::distr::Alphanumeric;
use rand::distr::Bernoulli;
use rand::prelude::Distribution;
use rand::rngs::SmallRng;
use rand::Rng;
use rand::SeedableRng;
use simplelog::CombinedLogger;
use simplelog::ConfigBuilder;
use simplelog::WriteLogger;
use simplelog::{ColorChoice, TermLogger, TerminalMode};
use tokio::io::AsyncReadExt;
use tokio::io::AsyncSeekExt;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio::runtime::Builder;
use tokio::signal::unix::SignalKind;

use crate::config::Config;
use crate::config::DomainName;
use crate::database::Database;
use crate::deb_mirror::parse_request_path;
use crate::deb_mirror::valid_architecture;
use crate::deb_mirror::valid_component;
use crate::deb_mirror::valid_distribution;
use crate::deb_mirror::valid_filename;
use crate::deb_mirror::valid_mirrorname;
use crate::deb_mirror::Mirror;
use crate::deb_mirror::Origin;
use crate::deb_mirror::OriginRef;
use crate::deb_mirror::ResourceFile;
use crate::error::ProxyCacheError;
use crate::http_range::http_datetime_to_systemtime;
use crate::http_range::http_parse_range;
use crate::http_range::systemtime_to_http_datetime;
use crate::humanfmt::HumanFmt;
use crate::logstore::LogStore;
use crate::ringbuffer::SumRingBuffer;
use crate::task_cache_scan::task_cache_scan;
use crate::task_cleanup::task_cleanup;
use crate::task_setup::task_setup;
use crate::web_interface::serve_web_interface;

type Client = hyper_util::client::legacy::Client<
    hyper_timeout::TimeoutConnector<HttpsConnector<HttpConnector>>,
    BoxBody<bytes::Bytes, ProxyCacheError>,
>;

const APP_NAME: &str = env!("CARGO_PKG_NAME");
const APP_VERSION: &str = env!("CARGO_PKG_VERSION");
const APP_USER_AGENT: &str = concat!(env!("CARGO_PKG_NAME"), "/", env!("CARGO_PKG_VERSION"),);

const RETENTION_TIME: Duration = Duration::from_secs(8 * 7 * 24 * 60 * 60); /* 8 weeks */

struct RateChecker {
    buf: SumRingBuffer<usize>,
    last: std::time::Instant,
    min_download_rate: NonZero<usize>,
}

impl RateChecker {
    const RATE_CHECK_TIME_SLOTS: NonZero<usize> = nonzero!(30); /* 30 seconds */

    #[must_use]
    fn new(min_download_rate: NonZero<usize>) -> Self {
        Self {
            buf: SumRingBuffer::new(Self::RATE_CHECK_TIME_SLOTS),
            last: Instant::now(),
            min_download_rate,
        }
    }

    fn add(&mut self, len: usize) {
        let elapsed = self.last.elapsed();
        let elapsed_secs = elapsed.as_secs();
        if elapsed_secs >= 1 {
            if elapsed_secs > 1 {
                warn!("More than 1 second elapsed since last poll ({elapsed:?})");
                for _ in 1..elapsed_secs {
                    self.buf.push(0);
                }
            }
            self.buf.push(len);
            self.last = self
                .last
                .checked_add(Duration::from_secs(elapsed_secs))
                .expect("Instant should be representable");
        } else {
            self.buf.add_back(len);
        }
    }

    fn check_fail(&self) -> Option<(usize, NonZero<usize>)> {
        if self.buf.is_full() {
            let total = self.buf.sum();
            if total / Self::RATE_CHECK_TIME_SLOTS < self.min_download_rate.get() {
                Some((total, self.buf.capacity()))
            } else {
                None
            }
        } else {
            None
        }
    }
}

enum RateCheckedBodyErr {
    DownloadRate((usize, NonZero<usize>)),
    Hyper(hyper::Error),
    ProxyCache(ProxyCacheError),
}

struct RateCheckedBody<D> {
    inner: Pin<Box<dyn Body<Data = D, Error = RateCheckedBodyErr> + Send + Sync + 'static>>,
    rchecker: RateChecker,
}

impl<D: bytes::Buf> RateCheckedBody<D> {
    fn new<B>(body: B, min_download_rate: NonZero<usize>) -> Self
    where
        B: Body<Data = D, Error = RateCheckedBodyErr> + Send + Sync + 'static,
        D: bytes::Buf,
    {
        Self {
            inner: Box::pin(body),
            rchecker: RateChecker::new(min_download_rate),
        }
    }
}

impl<D: bytes::Buf> Body for RateCheckedBody<D> {
    type Data = D;
    type Error = RateCheckedBodyErr;

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        if let Some((total_downloaded, time_limit)) = self.rchecker.check_fail() {
            return std::task::Poll::Ready(Some(Err(RateCheckedBodyErr::DownloadRate((
                total_downloaded,
                time_limit,
            )))));
        }

        let msg = self.inner.as_mut().poll_frame(cx);
        if let std::task::Poll::Ready(Some(Ok(ref frame))) = msg {
            if let Some(data) = frame.data_ref() {
                self.rchecker.add(data.remaining());
            }
        }

        msg
    }
}

enum ChannelBodyError {
    ClientDownloadRate(error::ClientDownloadRate),
    MirrorDownloadRate(error::MirrorDownloadRate),
}

struct ChannelBody {
    receiver: tokio::sync::mpsc::Receiver<Result<bytes::Bytes, ChannelBodyError>>,
    remaining_bytes: Option<u64>,
    complete: bool,
}

impl ChannelBody {
    #[must_use]
    fn new(
        receiver: tokio::sync::mpsc::Receiver<Result<bytes::Bytes, ChannelBodyError>>,
        size: NonZeroU64,
    ) -> Self {
        Self {
            receiver,
            remaining_bytes: Some(size.get()),
            complete: false,
        }
    }
}

impl Body for ChannelBody {
    type Data = bytes::Bytes;
    type Error = ProxyCacheError;

    fn size_hint(&self) -> hyper::body::SizeHint {
        match self.remaining_bytes {
            Some(val) => SizeHint::with_exact(val),
            None => SizeHint::default(),
        }
    }

    fn is_end_stream(&self) -> bool {
        self.complete
    }

    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        if self.is_end_stream() {
            return std::task::Poll::Ready(None);
        }

        let msg = self.receiver.poll_recv(cx);
        if matches!(msg, Ready(None)) {
            self.complete = true;
        }

        msg.map(|d| {
            d.map(|b| match b {
                Ok(data) => {
                    if let Some(remaining_bytes) = &mut self.remaining_bytes {
                        match remaining_bytes.overflowing_sub(data.len() as u64) {
                            (_, true) => self.remaining_bytes = None,
                            (val, false) => *remaining_bytes = val,
                        }
                    }

                    Ok(Frame::data(data))
                }
                Err(err) => Err(err.into()),
            })
        })
    }
}

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
    request: Request<BoxBody<bytes::Bytes, ProxyCacheError>>,
) -> Result<Response<Incoming>, hyper_util::client::legacy::Error> {
    const MAX_RETRIES: u32 = 5;

    if request.body().size_hint().exact() != Some(0) {
        warn_once_or_info!(
            "Request body is not empty, cannot retry. Request:  {:?}",
            request
        );
        return client.request(request).await;
    }

    let (parts, _body) = request.into_parts();

    let mut tries = 0;
    let mut sleep_prev = 1;
    let mut sleep_curr = 1;

    loop {
        let pre = tokio::time::Instant::now();

        let parts_clone = parts.clone();
        let body_clone = empty();
        let req_clone = Request::from_parts(parts_clone, body_clone);

        match client.request(req_clone).await {
            Ok(response) => return Ok(response),
            Err(err) if !err.is_connect() => {
                warn_once_or_info!("Request of internal client failed:  {err}  --  {err:?}");
                return Err(err);
            }
            Err(err) => {
                if tries >= MAX_RETRIES {
                    return Err(err);
                }

                tries += 1;

                tokio::time::sleep_until(pre + Duration::from_secs(sleep_curr)).await;

                let p = sleep_prev;
                sleep_prev = sleep_curr;
                sleep_curr += p;
                continue;
            }
        }
    }
}

#[must_use]
fn quick_response<T: Into<bytes::Bytes>>(
    status: hyper::StatusCode,
    message: T,
) -> Response<BoxBody<bytes::Bytes, ProxyCacheError>> {
    Response::builder()
        .status(status)
        .header(SERVER, HeaderValue::from_static(APP_NAME))
        .body(full(message))
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
    database: Option<Database>,
    conn_details: Option<ConnectionDetails>,
}

impl<S> DeliveryStreamBody<S> {
    #[must_use]
    fn new(
        stream: S,
        size: u64,
        partial: bool,
        database: Database,
        conn_details: ConnectionDetails,
    ) -> Self {
        Self {
            stream,
            start: Instant::now(),
            size,
            partial,
            transferred_bytes: 0,
            database: Some(database),
            conn_details: Some(conn_details),
        }
    }
}

impl<S, D, E> Body for DeliveryStreamBody<S>
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
                if let Ok(ref frame) = result {
                    if let Some(data) = frame.data_ref() {
                        *self.project().transferred_bytes += data.remaining() as u64;
                    }
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
        let db = project.database.take().expect("Option is set in new()");
        let cd = project.conn_details.take().expect("Option is set in new()");
        tokio::task::spawn(async move {
            let aliased = match cd.aliased_host {
                Some(alias) => Cow::Owned(format!(" aliased to host {alias}")),
                None => Cow::Borrowed(""),
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

                if let Err(err) = db
                    .register_deliviery(
                        &cd.mirror,
                        &cd.debname,
                        size,
                        duration,
                        partial,
                        cd.client.ip().to_canonical(),
                    )
                    .await
                {
                    error!("Failed to register delivery:  {err}");
                }
            } else if transferred_bytes == 0 {
                info!(
                    "Aborted serving cached file {} from mirror {}{} for client {} after {}",
                    cd.debname,
                    cd.mirror,
                    aliased,
                    cd.client.ip().to_canonical(),
                    HumanFmt::Time(duration)
                );
            } else {
                warn!(
                    "Failed to serve cached file {} from mirror {}{} for client {} after {} (size={}, transferred={}, rate={})",
                    cd.debname,
                    cd.mirror,
                    aliased,
                    cd.client.ip().to_canonical(),
                    HumanFmt::Time(duration),
                    HumanFmt::Size(size),
                    HumanFmt::Size(transferred_bytes),
                    HumanFmt::Rate(transferred_bytes, duration)
                );
            }
        });
    }
}

#[must_use]
async fn serve_cached_file(
    conn_details: ConnectionDetails,
    req: Request<hyper::body::Incoming>,
    database: Database,
    mut file: tokio::fs::File,
    file_path: &Path,
) -> Response<BoxBody<bytes::Bytes, ProxyCacheError>> {
    let aliased = match conn_details.aliased_host {
        Some(alias) => Cow::Owned(format!(" aliased to host {alias}")),
        None => Cow::Borrowed(""),
    };
    info!(
        "Serving cached file {} from mirror {}{} for client {}...",
        conn_details.debname,
        conn_details.mirror,
        aliased,
        conn_details.client.ip().to_canonical()
    );

    let metadata = match file.metadata().await {
        Ok(m) => m,
        Err(err) => {
            error!(
                "Error getting metadata of cached file {}:  {err}",
                file_path.display()
            );
            return quick_response(StatusCode::INTERNAL_SERVER_ERROR, "Cache Access Failure");
        }
    };

    let file_size = metadata.len();
    let modification_date = metadata
        .modified()
        .expect("platform should support modification time");

    let (http_status, content_length, content_range, partial) = match http_parse_range(
        req.headers().get(RANGE).and_then(|val| val.to_str().ok()),
        req.headers()
            .get(IF_RANGE)
            .and_then(|val| val.to_str().ok()),
        file_size,
        modification_date,
    ) {
        Some((content_range, start, content_length)) => {
            if let Err(err) = file.seek(std::io::SeekFrom::Start(start)).await {
                error!(
                    "Error seeking cached file {} to {start}/{file_size}:  {err}",
                    file_path.display()
                );
                return quick_response(StatusCode::INTERNAL_SERVER_ERROR, "Cache Access Failure");
            }
            (
                StatusCode::PARTIAL_CONTENT,
                content_length,
                Some(content_range),
                true,
            )
        }
        None => (StatusCode::OK, file_size, None, false),
    };

    let reader_stream =
        tokio_util::io::ReaderStream::with_capacity(file, global_config().buffer_size);
    let delivery_body = DeliveryStreamBody::new(
        reader_stream.map_ok(Frame::data),
        content_length,
        partial,
        database,
        conn_details,
    );
    let boxed_body = delivery_body.map_err(ProxyCacheError::Io).boxed();

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
        .body(boxed_body)
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

struct State {
    database: Database,
    https_client: Client,
    active_downloads: ActiveDownloads,
}

#[must_use]
async fn serve_volatile_file(
    conn_details: ConnectionDetails,
    req: Request<hyper::body::Incoming>,
    file: tokio::fs::File,
    file_path: &Path,
    state: State,
) -> Response<BoxBody<bytes::Bytes, ProxyCacheError>> {
    let (is_downloading, status) = state
        .active_downloads
        .insert(conn_details.mirror.clone(), conn_details.debname.clone());

    if is_downloading {
        info!(
            "Serving file {} already in download from mirror {} for client {}...",
            conn_details.debname,
            conn_details.mirror,
            conn_details.client.ip().to_canonical()
        );
        return serve_downloading_file(conn_details, req, state.database, status).await;
    }

    let local_modification_time = match file.metadata().await {
        Ok(data) => data
            .modified()
            .expect("Platform should support modification timestamps"),
        Err(err) => {
            error!(
                "Failed to get modification timestamp of file {}:  {err}",
                file_path.display()
            );
            return quick_response(StatusCode::INTERNAL_SERVER_ERROR, "Cache Access Failure");
        }
    };

    // TODO: fix for mirror responding 304 to outdated if-modified-since
    // let volatile = match local_modification_time.elapsed().map(|dur| dur.as_secs()) {
    //     Ok(age) if age > 24 * 60 * 60 => {
    //         debug!(
    //             "File {} from mirror {} is {} old, forcing refresh",
    //             conn_details.debname,
    //             conn_details.mirror,
    //             HumanFmt::Time(Duration::from_secs(age))
    //         );
    //         CacheFileStat::Override
    //     }
    //     _ => CacheFileStat::Volatile((file, file_path, local_modification_time)),
    // };

    serve_new_file(
        conn_details,
        status,
        req,
        CacheFileStat::Volatile((file, file_path, local_modification_time)),
        state,
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
enum ActiveDownloadStatus {
    Init,
    Download(PathBuf, NonZeroU64, tokio::sync::watch::Receiver<u32>),
    Finished(PathBuf),
    Aborted(ProxyCacheError),
}

#[derive(Clone, Debug)]
struct ActiveDownloads {
    inner: Arc<
        std::sync::Mutex<HashMap<ActiveDownloadKey, Arc<tokio::sync::Mutex<ActiveDownloadStatus>>>>,
    >,
}

impl ActiveDownloads {
    #[must_use]
    fn new() -> Self {
        Self {
            inner: Arc::new(std::sync::Mutex::new(HashMap::new())),
        }
    }

    #[must_use]
    fn len(&self) -> usize {
        self.inner
            .lock()
            .expect("other users should not panic")
            .len()
    }

    #[must_use]
    fn insert(
        &self,
        mirror: Mirror,
        debname: String,
    ) -> (bool, Arc<tokio::sync::Mutex<ActiveDownloadStatus>>) {
        let key = ActiveDownloadKey { mirror, debname };
        let mut ads = self.inner.lock().expect("other users should not panic");

        // TODO: use try_insert() once stable: https://github.com/rust-lang/rust/issues/82766
        if let Some(status) = ads.get(&key) {
            (true, status.clone())
        } else {
            let status = Arc::new(tokio::sync::Mutex::new(ActiveDownloadStatus::Init));
            let was_present = ads.insert(key, status.clone());
            assert!(was_present.is_none());
            (false, status)
        }
    }

    fn remove(&self, mirror: &Mirror, debname: &str) {
        let key = ActiveDownloadKeyRef { mirror, debname };
        let was_present = self
            .inner
            .lock()
            .expect("other users should not panic")
            .remove(&key as &dyn AsActiveDownloadKeyRef);
        assert!(was_present.is_some());
    }

    #[must_use]
    fn download_size(&self) -> u64 {
        let ads = self.inner.lock().expect("other users should not panic");

        tokio::task::block_in_place(move || {
            let mut sum = 0;

            for (_key, download) in ads.iter() {
                let d = download.blocking_lock();
                if let ActiveDownloadStatus::Download(_, size, _) = &*d {
                    sum += size.get();
                }
            }

            sum
        })
    }

    #[must_use]
    fn download_count(&self) -> usize {
        let ads = self.inner.lock().expect("other users should not panic");

        tokio::task::block_in_place(move || {
            let mut count = 0;

            for (_key, download) in ads.iter() {
                let d = download.blocking_lock();
                match &*d {
                    ActiveDownloadStatus::Init
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

#[expect(clippy::too_many_lines)]
async fn download_file(
    database: Database,
    conn_details: &ConnectionDetails,
    warn_on_override: bool,
    status: &Arc<tokio::sync::Mutex<ActiveDownloadStatus>>,
    body: Incoming,
    output: (tokio::fs::File, PathBuf),
    tx: tokio::sync::watch::Sender<u32>,
) {
    trace!(
        "Starting download of file {} from mirror {} for client {}...",
        conn_details.debname,
        conn_details.mirror,
        conn_details.client.ip().to_canonical()
    );
    let start = Instant::now();

    let mut bytes = 0;
    let mut last_send_bytes = 0;
    let mut send_id = 1;
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
                    RateCheckedBodyErr::DownloadRate((total_size, timeout_secs)) => {
                        *status.lock().await = ActiveDownloadStatus::Aborted(
                            ProxyCacheError::MirrorDownloadRate(error::MirrorDownloadRate {
                                total_size,
                                timeout_secs,
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
                        *status.lock().await =
                            ActiveDownloadStatus::Aborted(ProxyCacheError::Hyper(herr));
                    }
                    RateCheckedBodyErr::ProxyCache(perr) => {
                        error!(
                            "Error extracting frame from body for file {} from mirror {}:  {perr}",
                            conn_details.debname, conn_details.mirror
                        );
                        *status.lock().await = ActiveDownloadStatus::Aborted(perr);
                    }
                }

                return;
            }
        };
        if let Ok(mut chunk) = frame.into_data() {
            bytes += chunk.len() as u64;
            if let Err(err) = writer.write_all_buf(&mut chunk).await {
                error!("Error writing to file {}:  {err}", output.1.display());
                *status.lock().await = ActiveDownloadStatus::Aborted(err.into());
                return;
            }
            if connected && bytes > buf_size as u64 + last_send_bytes {
                if let Err(err) = tx.send(send_id) {
                    error!(
                        "All receivers of watch channel for file {} from mirror {} died:  {err}",
                        conn_details.debname, conn_details.mirror
                    );
                    connected = false;
                }
                send_id += 1;
                last_send_bytes = bytes;
            }
        }
    }

    if let Err(err) = writer.flush().await {
        error!("Error writing to file {}:  {err}", output.1.display());
        *status.lock().await = ActiveDownloadStatus::Aborted(err.into());
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
        conn_details.subdir.unwrap_or(Path::new("")),
    ]
    .iter()
    .collect();

    if let Err(err) = tokio::fs::create_dir_all(&dest_dir).await {
        if err.kind() != tokio::io::ErrorKind::AlreadyExists {
            error!(
                "Failed to create destination directory {}:  {err}",
                dest_dir.display()
            );
            *status.lock().await = ActiveDownloadStatus::Aborted(err.into());
            return;
        }
    }

    let dest_path: PathBuf = [
        cache_dir,
        Path::new(
            &conn_details
                .aliased_host
                .unwrap_or(&conn_details.mirror.host),
        ),
        Path::new(&conn_details.mirror.path),
        conn_details.subdir.unwrap_or(Path::new("")),
        Path::new(&conn_details.debname),
    ]
    .iter()
    .collect();

    debug!("Saving downloaded file to `{}`", dest_path.display());

    {
        let mut locked_status = status.lock().await;

        /* Should only happen for concurrent downloads from aliased mirrors */
        if warn_on_override && tokio::fs::try_exists(&dest_path).await.unwrap_or(false) {
            warn!(
                "Target file `{}` already exists, overriding... (aliased={})",
                dest_path.display(),
                conn_details.aliased_host.is_some()
            );
        }

        match tokio::fs::rename(&output.1, &dest_path).await {
            Ok(()) => *locked_status = ActiveDownloadStatus::Finished(dest_path),
            Err(err) => {
                error!(
                    "Failed to rename file `{}` to `{}`:  {err}",
                    output.1.display(),
                    dest_path.display()
                );
                *locked_status = ActiveDownloadStatus::Aborted(err.into());
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

    if let Err(err) = database
        .register_download(
            &conn_details.mirror,
            &conn_details.debname,
            bytes,
            elapsed,
            conn_details.client.ip().to_canonical(),
        )
        .await
    {
        error!("Failed to register download:  {err}");
    }
}

#[must_use]
#[expect(clippy::too_many_lines)]
async fn serve_unfinished_file(
    conn_details: ConnectionDetails,
    database: Database,
    mut file: tokio::fs::File,
    file_path: PathBuf,
    status: Arc<tokio::sync::Mutex<ActiveDownloadStatus>>,
    content_length: NonZeroU64,
    mut receiver: tokio::sync::watch::Receiver<u32>,
) -> Response<BoxBody<bytes::Bytes, ProxyCacheError>> {
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
            "Starting stream task for downloading file {} from mirror {} with length {content_length} for client {}...",
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
                let st = status.lock().await;
                match *st {
                    ActiveDownloadStatus::Finished(_) => {
                        finished = true;
                        continue;
                    }
                    ActiveDownloadStatus::Aborted(ref err) => {
                        match err {
                            ProxyCacheError::ClientDownloadRate(cdr) => {
                                let _ = tx
                                    .send(Err(ChannelBodyError::ClientDownloadRate((*cdr).clone())))
                                    .await;
                            }
                            ProxyCacheError::MirrorDownloadRate(mdr) => {
                                let _ = tx
                                    .send(Err(ChannelBodyError::MirrorDownloadRate((*mdr).clone())))
                                    .await;
                            }
                            _ => {
                                warn!(
                                    "Download of file `{}` aborted, cancelling stream: {err}",
                                    file_path.display()
                                );
                            }
                        }

                        return;
                    }
                    _ => {
                        error!(
                            "Invalid download state {:?} of file `{}`, cancelling stream",
                            *st,
                            file_path.display()
                        );
                        return;
                    }
                }
            }
        }

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

        /* Perform cleanup before database operation */
        drop(reader);
        drop(receiver);
        drop(status);
        drop(tx);

        if let Err(err) = database
            .register_deliviery(
                &conn_details.mirror,
                &conn_details.debname,
                bytes,
                elapsed,
                false,
                conn_details.client.ip().to_canonical(),
            )
            .await
        {
            error!("Failed to register delivery:  {err}");
        }
    });

    let response_builder = Response::builder()
        .status(200)
        .header(CONNECTION, HeaderValue::from_static("keep-alive"))
        .header(
            CONTENT_TYPE,
            HeaderValue::from_static("application/vnd.debian.binary-package"),
        )
        .header(ACCEPT_RANGES, HeaderValue::from_static("bytes"))
        .header(SERVER, HeaderValue::from_static(APP_NAME))
        .header(CONTENT_LENGTH, HeaderValue::from(content_length.get()))
        .header(
            LAST_MODIFIED,
            HeaderValue::try_from(systemtime_to_http_datetime(create_time))
                .expect("Http datetime is valid"),
        );

    let channel_body = ChannelBody::new(rx, content_length);

    let response = match global_config().min_download_rate {
        Some(min_download_rate) => {
            let checked_channel_body = RateCheckedBody::new(
                channel_body.map_err(RateCheckedBodyErr::ProxyCache),
                min_download_rate,
            );
            response_builder
                .body(BoxBody::new(checked_channel_body.map_err(
                    move |rerr| match rerr {
                        RateCheckedBodyErr::DownloadRate((total_size, timeout_secs)) => {
                            ProxyCacheError::ClientDownloadRate(error::ClientDownloadRate {
                                total_size,
                                timeout_secs,
                                client_ip: conn_details.client.ip(),
                            })
                        }
                        RateCheckedBodyErr::Hyper(herr) => ProxyCacheError::Hyper(herr),
                        RateCheckedBodyErr::ProxyCache(perr) => perr,
                    },
                )))
                .expect("HTTP response is valid")
        }
        None => response_builder
            .body(BoxBody::new(channel_body))
            .expect("HTTP response is valid"),
    };

    trace!("Outgoing response: {response:?}");

    response
}

#[must_use]
async fn serve_downloading_file(
    conn_details: ConnectionDetails,
    req: Request<hyper::body::Incoming>,
    database: Database,
    status: Arc<tokio::sync::Mutex<ActiveDownloadStatus>>,
) -> Response<BoxBody<bytes::Bytes, ProxyCacheError>> {
    let mut slept_once = false;
    let mut not_found_once = false;

    loop {
        let st = status.lock().await;

        match &*st {
            ActiveDownloadStatus::Aborted(_err) => {
                drop(st);
                return quick_response(StatusCode::INTERNAL_SERVER_ERROR, "Download Aborted");
            }
            ActiveDownloadStatus::Init => {
                drop(st);
                if slept_once {
                    // TODO: fix on slow upstream connection; mayge store an Instant in Init?
                    error!("Download did not leave Init state");
                    return quick_response(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "Download not started",
                    );
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
                slept_once = true;
            }
            ActiveDownloadStatus::Finished(path) => {
                let file = match tokio::fs::File::open(&path).await {
                    Ok(f) => f,
                    Err(err) => {
                        error!(
                            "Failed to open downloaded file `{}`:  {err}",
                            path.display()
                        );
                        return quick_response(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "Cache Access Failure",
                        );
                    }
                };
                let path_clone = path.clone();
                drop(st);

                return serve_cached_file(conn_details, req, database, file, &path_clone).await;
            }
            ActiveDownloadStatus::Download(path, content_length, receiver) => {
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
                    database,
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
    #[expect(dead_code)]
    Override,
    New,
}

fn is_host_allowed(requested_host: &str) -> bool {
    global_config()
        .allowed_mirrors
        .iter()
        .any(|host| host.permits(requested_host))
}

#[must_use]
#[expect(clippy::too_many_lines)]
async fn serve_new_file(
    conn_details: ConnectionDetails,
    status: Arc<tokio::sync::Mutex<ActiveDownloadStatus>>,
    req: Request<hyper::body::Incoming>,
    cfstate: CacheFileStat<'_>,
    state: State,
) -> Response<BoxBody<bytes::Bytes, ProxyCacheError>> {
    // TODO: upstream constant
    const PROXY_CONNECT: HeaderName = HeaderName::from_static("proxy-connext");

    let is_volatile = matches!(cfstate, CacheFileStat::Volatile(_));
    let prev_file_size =
        if let CacheFileStat::Volatile((file, file_path, _local_modification_time)) = &cfstate {
            match file.metadata().await.map(|md| md.size()) {
                Ok(s) => s,
                Err(err) => {
                    error!(
                        "Failed to get file size of file `{}`:  {err}",
                        file_path.display()
                    );
                    0
                }
            }
        } else {
            0
        };
    let mut client_modified_since = None;
    let mut max_age = 300;

    for (name, value) in req.headers() {
        match name {
            &USER_AGENT | &RANGE | &IF_RANGE | &HOST | &ACCEPT => (),
            n if n == PROXY_CONNECT => (),
            /*
             * TODO:
             * Ignore client cache settings for now.
             * For new files they are irrelevant.
             * We assume pool files never change and for dists file we set them manually.
             */
            &CACHE_CONTROL => {
                if let Ok(s) = value.to_str() {
                    for p in s.split(',') {
                        if let Some((key, val)) = p.split_once('=') {
                            if key == "max-age" {
                                if let Ok(v) = val.parse::<u32>() {
                                    max_age = v;
                                }
                            }
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

    if req.body().size_hint().exact() != Some(0) {
        warn_once_or_info!("Download request has non empty body, not forwarding body: {req:?}");
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

    let fwd_host = match &req.headers().get(HOST) {
        Some(h) => (*h).clone(),
        None => HeaderValue::from_str(&conn_details.mirror.host)
            .expect("connection host should be valid"),
    };

    let mut fwd_request = Request::builder()
        .method(Method::GET)
        .uri(req.uri())
        .header(USER_AGENT, HeaderValue::from_static(APP_USER_AGENT))
        .header(HOST, fwd_host.clone())
        .body(empty())
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
            HeaderValue::from_str(&format!("max-age={max_age}")).expect("string is valid"),
        );
        assert!(!r);
    }

    trace!("Forwarded request: {fwd_request:?}");

    let mut fwd_response = match request_with_retry(&state.https_client, fwd_request).await {
        Ok(r) => r,
        Err(err) => {
            warn!(
                "Proxy request failed to mirror {}:  {err}",
                conn_details.mirror
            );
            state
                .active_downloads
                .remove(&conn_details.mirror, &conn_details.debname);
            return quick_response(StatusCode::SERVICE_UNAVAILABLE, "Proxy request failed");
        }
    };

    trace!("Forwarded response: {fwd_response:?}");

    if fwd_response.status() == StatusCode::MOVED_PERMANENTLY {
        if let Some(moved_uri) = fwd_response
            .headers()
            .get(LOCATION)
            .and_then(|lc| lc.to_str().ok())
            .and_then(|lc_str| lc_str.parse::<hyper::Uri>().ok())
        {
            debug!("Requested URI: {}, Moved URI: {moved_uri:?}", req.uri());

            if moved_uri.host().is_some_and(is_host_allowed) {
                let mut redirected_request = Request::builder()
                    .method(Method::GET)
                    .uri(moved_uri)
                    .header(USER_AGENT, HeaderValue::from_static(APP_USER_AGENT))
                    .header(HOST, fwd_host.clone())
                    .body(empty())
                    .expect("request should be valid");

                if let CacheFileStat::Volatile((_file, _file_path, local_modification_time)) =
                    &cfstate
                {
                    let date_fmt = systemtime_to_http_datetime(*local_modification_time);

                    let r = redirected_request.headers_mut().append(
                        IF_MODIFIED_SINCE,
                        HeaderValue::try_from(date_fmt).expect("HTTP datetime should be valid"),
                    );
                    assert!(!r);

                    let r = redirected_request.headers_mut().append(
                        CACHE_CONTROL,
                        HeaderValue::from_str(&format!("max-age={max_age}"))
                            .expect("string is valid"),
                    );
                    assert!(!r);
                }

                trace!("Forwarded redirected request: {redirected_request:?}");

                let redirected_response =
                    match request_with_retry(&state.https_client, redirected_request).await {
                        Ok(r) => r,
                        Err(err) => {
                            warn!("Proxy redirected request to host {fwd_host:?} failed:  {err}");
                            state
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
            }
        }
    }

    if let CacheFileStat::Volatile((file, file_path, local_modification_time)) = cfstate {
        if fwd_response.status() == StatusCode::NOT_MODIFIED {
            state
                .active_downloads
                .remove(&conn_details.mirror, &conn_details.debname);

            let Some(client_modified_since) = client_modified_since else {
                return serve_cached_file(conn_details, req, state.database, file, file_path).await;
            };

            if let Some(client_modified_time) = client_modified_since
                .to_str()
                .ok()
                .and_then(http_datetime_to_systemtime)
            {
                if client_modified_time >= local_modification_time {
                    info!(
                        "Serving info about up-to-date cached file {} from mirror {} for client {}",
                        conn_details.debname,
                        conn_details.mirror,
                        conn_details.client.ip().to_canonical()
                    );

                    /*
                     * Response {
                     *     status: 304,
                     *     version: HTTP/1.1,
                     *     headers: {
                     *         "connection": "keep-alive",
                     *         "date": "Sat, 08 Jun 2024 12:50:39 GMT",
                     *         "via": "1.1 varnish",
                     *         "cache-control": "public, max-age=120",
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

                    let mut response = Response::builder()
                        .status(StatusCode::NOT_MODIFIED)
                        .header(CONNECTION, HeaderValue::from_static("keep-alive"))
                        .header(SERVER, HeaderValue::from_static(APP_NAME))
                        .header(
                            CACHE_CONTROL,
                            HeaderValue::from_str(&format!("public, max-age={max_age}"))
                                .expect("string is valid"),
                        ) // TODO: send CACHE_CONTROL in other branches as well
                        .header(
                            AGE,
                            HeaderValue::from_str(&format!(
                                "{}",
                                local_modification_time
                                    .elapsed()
                                    .map(|dur| dur.as_secs())
                                    .unwrap_or(0)
                            ))
                            .expect("string is valid"),
                        ) // TODO: send AGE in other branches as well
                        .body(empty())
                        .expect("HTTP response is valid");

                    if let Some(date) = fwd_response.headers_mut().remove(DATE) {
                        let r = response.headers_mut().append(DATE, date);
                        assert!(!r);
                    }

                    trace!("Outgoing response of up-to-date cached file: {response:?}");

                    return response;
                }
            }

            info!("File {} from mirror {} is up-to-date in cache, serving to client {} with older version",
                conn_details.debname,
                conn_details.mirror,
                conn_details.client.ip().to_canonical()
            );

            return serve_cached_file(conn_details, req, state.database, file, file_path).await;
        }

        debug!(
            "File `{}` is outdated (status={}), downloading new version",
            file_path.display(),
            fwd_response.status()
        );
    }

    if fwd_response.status() != StatusCode::OK {
        warn!(
            "Request failed with code {}, got response {fwd_response:?}",
            fwd_response.status()
        );
        state
            .active_downloads
            .remove(&conn_details.mirror, &conn_details.debname);

        let (parts, body) = fwd_response.into_parts();

        let body = BoxBody::new(body.map_err(ProxyCacheError::Hyper));

        let response = Response::from_parts(parts, body);

        trace!("Outgoing response: {response:?}");

        return response;
    }

    let Some(content_length) = fwd_response.headers().get(CONTENT_LENGTH).and_then(|hv| {
        hv.to_str()
            .ok()
            .and_then(|ct| ct.parse::<NonZeroU64>().ok())
    }) else {
        warn!(
            "Could not extract content-length from header for file `{}` from mirror {}: {fwd_response:?}",
           conn_details.debname, conn_details.mirror);
        state
            .active_downloads
            .remove(&conn_details.mirror, &conn_details.debname);
        return quick_response(
            StatusCode::BAD_GATEWAY,
            "Upstream resource has no content length",
        );
    };

    if let Some(quota) = global_config().disk_quota {
        let mut mg_cache_size = RUNTIMEDETAILS
            .get()
            .expect("global is set in main()")
            .cache_size
            .lock()
            .expect("other uses should not panic");
        let quota_reached = content_length
            .checked_add(*mg_cache_size)
            .is_some_and(|s| s > quota);

        if quota_reached {
            let cache_size = *mg_cache_size;
            drop(mg_cache_size);
            warn!(
                "Disk quota reached: file={} cache_size={} content_length={} quota={}",
                conn_details.debname, cache_size, content_length, quota
            );
            state
                .active_downloads
                .remove(&conn_details.mirror, &conn_details.debname);
            return quick_response(StatusCode::SERVICE_UNAVAILABLE, "Disk quota reached");
        }

        *mg_cache_size = mg_cache_size
            .checked_add(content_length.get())
            .expect("should not overflow by previous check");
        *mg_cache_size = mg_cache_size
            .checked_sub(prev_file_size)
            .expect("size should not underflow");
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
                let mut mg_cache_size = RUNTIMEDETAILS
                    .get()
                    .expect("global is set in main()")
                    .cache_size
                    .lock()
                    .expect("other uses should not panic");

                *mg_cache_size = mg_cache_size.saturating_sub(content_length.get());
            }

            state
                .active_downloads
                .remove(&conn_details.mirror, &conn_details.debname);
            return quick_response(StatusCode::INTERNAL_SERVER_ERROR, "Cache Access Failure");
        }
    };

    info!(
        "Downloading and serving new file `{}` from mirror {} for client {}...",
        conn_details.debname,
        conn_details.mirror,
        conn_details.client.ip().to_canonical()
    );

    let (tx, rx) = tokio::sync::watch::channel(0);

    *status.lock().await = ActiveDownloadStatus::Download(outpath.clone(), content_length, rx);

    let cd = conn_details.clone();
    let st = status.clone();
    let db = state.database.clone();
    let curr_downloads = state.active_downloads.download_count();
    tokio::task::spawn(async move {
        download_file(db, &cd, !is_volatile, &st, body, (outfile, outpath), tx).await;
        if !matches!(*(st.lock().await), ActiveDownloadStatus::Finished(_)) {
            let mut mg_cache_size = RUNTIMEDETAILS
                .get()
                .expect("global is set in main()")
                .cache_size
                .lock()
                .expect("other uses should not panic");

            *mg_cache_size = mg_cache_size.saturating_sub(content_length.get());
        }
        state.active_downloads.remove(&cd.mirror, &cd.debname);
    });

    let gcfg = global_config();

    if !is_volatile
        && gcfg.experimental_parallel_hack_enabled
        && gcfg
            .experimental_parallel_hack_minsize
            .is_some_and(|size| content_length > size)
    {
        #[expect(clippy::cast_precision_loss)]
        let p = (1.0
            - curr_downloads.saturating_sub(1) as f64 * gcfg.experimental_parallel_hack_factor)
            .max(0.0);
        let d = Bernoulli::new(p).expect("p is valid");
        let v = d.sample(&mut rand::rng());
        debug!("{v} is from a Bernoulli distribution with success probability {p} from count {curr_downloads}");

        if v {
            debug!(
                "Trying parallel download hack for client {} and file {} with code {} and retry after value {}",
                conn_details.client.ip().to_canonical(),
                conn_details.debname,
                gcfg.experimental_parallel_hack_statuscode,
                gcfg.experimental_parallel_hack_retryafter
            );

            return Response::builder()
                .status(gcfg.experimental_parallel_hack_statuscode)
                .header(SERVER, HeaderValue::from_static(APP_NAME))
                .header(
                    RETRY_AFTER,
                    HeaderValue::from_str(&gcfg.experimental_parallel_hack_retryafter.to_string())
                        .expect("string is valid"),
                )
                .body(full("Parallel Download Hack"))
                .expect("Response is valid");
        }
    }

    serve_downloading_file(conn_details, req, state.database, status).await
}

/// Create a TCP connection to host:port, build a tunnel between the connection and
/// the upgraded connection
async fn tunnel(
    client: SocketAddr,
    upgraded: hyper::upgrade::Upgraded,
    host: &str,
    port: NonZeroU16,
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
async fn process_cache_request(
    conn_details: ConnectionDetails,
    req: Request<hyper::body::Incoming>,
    volatile: bool,
    state: State,
) -> Response<BoxBody<bytes::Bytes, ProxyCacheError>> {
    let cache_path: PathBuf = [
        &global_config().cache_directory,
        Path::new(
            &conn_details
                .aliased_host
                .unwrap_or(&conn_details.mirror.host),
        ),
        Path::new(&conn_details.mirror.path),
        conn_details.subdir.unwrap_or(Path::new("")),
        Path::new(&conn_details.debname),
    ]
    .iter()
    .collect();

    match tokio::fs::File::open(&cache_path).await {
        Ok(file) => {
            if volatile {
                serve_volatile_file(conn_details, req, file, &cache_path, state).await
            } else {
                serve_cached_file(conn_details, req, state.database, file, &cache_path).await
            }
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            let (is_downloading, status) = state
                .active_downloads
                .insert(conn_details.mirror.clone(), conn_details.debname.clone());

            if is_downloading {
                info!(
                    "Serving file `{}` already in download from mirror {} for client {}...",
                    conn_details.debname,
                    conn_details.mirror,
                    conn_details.client.ip().to_canonical()
                );
                serve_downloading_file(conn_details, req, state.database, status).await
            } else {
                serve_new_file(conn_details, status, req, CacheFileStat::New, state).await
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
) -> Response<BoxBody<bytes::Bytes, ProxyCacheError>> {
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
        warn!("Invalid CONNECT address: {}", req.uri());
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
                    if err.kind() == ErrorKind::NotConnected
                        || err.kind() == ErrorKind::ConnectionReset
                    {
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
                };
            }
            Err(err) => error!(
                "Error upgrading connection for client {} to {host}:{port}:  {err}",
                client.ip().to_canonical()
            ),
        }
    });

    Response::new(empty())
}

async fn pre_process_client_request_wrapper(
    client: SocketAddr,
    req: Request<hyper::body::Incoming>,
    state: State,
) -> Result<Response<BoxBody<bytes::Bytes, ProxyCacheError>>, ProxyCacheError> {
    Ok(pre_process_client_request(client, req, state).await)
}

#[must_use]
#[expect(clippy::too_many_lines)]
async fn pre_process_client_request(
    client: SocketAddr,
    req: Request<hyper::body::Incoming>,
    state: State,
) -> Response<BoxBody<bytes::Bytes, ProxyCacheError>> {
    trace!("Incoming request: {req:?}");

    {
        let allowed_clients = global_config().allowed_clients.as_slice();
        if !allowed_clients.is_empty()
            && !allowed_clients
                .iter()
                .any(|ac| ac.contains(&client.ip().to_canonical()))
        {
            warn_once_or_info!("Unauthorized client {}", client.ip().to_canonical());
            return quick_response(hyper::StatusCode::FORBIDDEN, "Unauthorized client");
        }
    }

    if Method::CONNECT == req.method() {
        return connect_response(client, req);
    }

    if Method::GET != req.method() {
        warn_once_or_info!("Unsupported request method {}", req.method());
        return quick_response(hyper::StatusCode::BAD_REQUEST, "Method not supported");
    }

    let requested_host = match req.uri().authority().map(hyper::http::uri::Authority::host) {
        Some(h) => h.to_owned(),
        None => return serve_web_interface(req, state.database).await,
    };

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

    let aliased_host = global_config()
        .aliases
        .iter()
        .find(|alias| alias.aliases.binary_search(&requested_host).is_ok())
        .map(|alias| &alias.main);

    let requested_path = req.uri().path();

    debug!("Requested host: `{requested_host}`; Aliased host: `{aliased_host:?}`; Requested path: `{requested_path}`");

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

                    debug!("Decoded mirrorname: `{mirrorname}`; Decoded debname: `{debname}`");

                    let conn_details = ConnectionDetails {
                        client,
                        mirror: Mirror {
                            host: requested_host,
                            path: mirrorname.into_owned(),
                        },
                        aliased_host,
                        debname: debname.into_owned(),
                        subdir: None,
                    };

                    return process_cache_request(conn_details, req, false, state).await;
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

                debug!("Decoded mirrorname: `{mirrorname}`; Decoded distribution: `{distribution}`; Decoded filename: `{filename}`");

                let conn_details = ConnectionDetails {
                    client,
                    mirror: Mirror {
                        host: requested_host,
                        path: mirrorname.into_owned(),
                    },
                    aliased_host,
                    debname: format!("{distribution}_{filename}"),
                    subdir: Some(Path::new("dists")),
                };

                return process_cache_request(conn_details, req, true, state).await;
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

                debug!("Decoded mirrorname: `{mirrorname}`; Decoded distribution: `{distribution}`; Decoded component: `{component}`; Decoded architecture: `{architecture}`; Decoded filename: `{filename}`");

                let conn_details = ConnectionDetails {
                    client,
                    mirror: Mirror {
                        host: requested_host,
                        path: mirrorname.into_owned(),
                    },
                    aliased_host,
                    debname: format!("{distribution}_{component}_{architecture}_{filename}"),
                    subdir: Some(Path::new("dists")),
                };

                match architecture.as_ref() {
                    // TODO: cache some of them?
                    "dep11" | "i18n" | "source" => (),
                    _ => {
                        let orig = OriginRef {
                            mirror: &conn_details.mirror,
                            distribution: distribution.as_ref(),
                            component: component.as_ref(),
                            architecture: architecture.as_ref(),
                        };
                        if let Err(err) = state.database.add_origin(&orig).await {
                            error!("Error registering origin {orig:?}:  {err}");
                        }
                    }
                }

                return process_cache_request(conn_details, req, true, state).await;
            }
        }
    }

    match req.method() {
        /* Simple proxy (without any caching) */
        &Method::GET => {
            /*
             * http://deb.debian.org/debian-debug/dists/sid-debug/main/binary-i386/Packages.diff/T-2024-09-24-2005.48-F-2024-09-23-2021.00.gz
             * http://deb.debian.org/debian/dists/unstable/main/i18n/Translation-en.diff/T-2024-10-03-0804.49-F-2024-10-02-2011.04.gz
             * http://deb.debian.org/debian/dists/sid/main/source/Sources.diff/T-2024-10-03-1409.04-F-2024-10-03-1409.04.gz
             */
            fn ignore_uncached_path(uri_path: &str) -> bool {
                uri_path.contains("/by-hash/SHA256/")
                    || uri_path.contains("/Packages.diff/T-")
                    || uri_path.contains("/Translation-en.diff/T-")
                    || uri_path.contains("/Sources.diff/T-")
            }

            if ignore_uncached_path(requested_path) {
                info!("Proxying (without caching) request {}", req.uri());
            } else {
                warn_once_or_info!("Proxying (without caching) request {}", req.uri());
            }

            let (mut parts, body) = req.into_parts();
            parts.headers.insert(
                USER_AGENT,
                APP_USER_AGENT.parse().expect("app user agent is ASCII"),
            );

            let mut parts_cloned = parts.clone();
            let is_empty_body = body.size_hint().exact() == Some(0);

            let body = body.map_err(ProxyCacheError::Hyper).boxed();
            // TODO: tweak http version?
            let fwd_request = Request::from_parts(parts, body);

            trace!("Forwarded request: {fwd_request:?}");

            let fwd_response = match request_with_retry(&state.https_client, fwd_request).await {
                Ok(r) => r,
                Err(err) => {
                    warn!("Proxy request to host {requested_host} failed:  {err}");
                    return quick_response(StatusCode::SERVICE_UNAVAILABLE, "Proxy request failed");
                }
            };

            trace!("Forwarded response: {fwd_response:?}");

            if fwd_response.status().is_success() || fwd_response.status().is_redirection() {
                if let Some(origin) =
                    Origin::from_path(parts_cloned.uri.path(), requested_host.clone())
                {
                    debug!("Extracted origin: {origin:?}");

                    match origin.architecture.as_str() {
                        // TODO: cache some of them?
                        "dep11" | "i18n" | "source" => (),
                        _ => {
                            if let Err(err) = state.database.add_origin(&origin.as_ref()).await {
                                error!("Error registering origin {origin:?}:  {err}");
                            }
                        }
                    }
                }
            }

            if fwd_response.status() == StatusCode::MOVED_PERMANENTLY {
                if let Some(moved_uri) = fwd_response
                    .headers()
                    .get(LOCATION)
                    .and_then(|lc| lc.to_str().ok())
                    .and_then(|lc_str| lc_str.parse::<hyper::Uri>().ok())
                {
                    debug!(
                        "Requested URI: {}, Moved URI: {moved_uri}, Body is-empty: {}",
                        parts_cloned.uri, is_empty_body
                    );

                    if moved_uri.host().is_some_and(is_host_allowed) {
                        parts_cloned.uri = moved_uri;
                        let redirected_request = Request::from_parts(parts_cloned, empty());

                        trace!("Redirected request: {redirected_request:?}");

                        let redirected_response = match request_with_retry(
                            &state.https_client,
                            redirected_request,
                        )
                        .await
                        {
                            Ok(r) => r,
                            Err(err) => {
                                warn!(
                                    "Redirected proxy request to host {requested_host} failed:  {err}"
                                );
                                return quick_response(
                                    StatusCode::SERVICE_UNAVAILABLE,
                                    "Proxy request failed",
                                );
                            }
                        };

                        trace!("Redirected response: {redirected_response:?}");

                        let (parts, body) = redirected_response.into_parts();

                        let body = BoxBody::new(body.map_err(ProxyCacheError::Hyper));

                        let response = Response::from_parts(parts, body);

                        trace!("Outgoing response: {response:?}");

                        return response;
                    }
                }
            }

            let (parts, body) = fwd_response.into_parts();

            let body = BoxBody::new(body.map_err(ProxyCacheError::Hyper));

            let response = Response::from_parts(parts, body);

            trace!("Outgoing response: {response:?}");

            response
        }

        /* Return the 404 Not Found for other routes. */
        _ => quick_response(StatusCode::NOT_FOUND, "Resource not found"),
    }
}

#[must_use]
fn empty() -> BoxBody<bytes::Bytes, ProxyCacheError> {
    Empty::<bytes::Bytes>::new()
        .map_err(|never| match never {})
        .boxed()
}

#[must_use]
fn full<T: Into<bytes::Bytes>>(chunk: T) -> BoxBody<bytes::Bytes, ProxyCacheError> {
    Full::new(chunk.into())
        .map_err(|never| match never {})
        .boxed()
}

#[must_use]
fn is_iokind(err: &hyper::Error, kind: std::io::ErrorKind) -> bool {
    if let Some(err) = std::error::Error::source(&err) {
        if let Some(ioerr) = err.downcast_ref::<std::io::Error>() {
            if ioerr.kind() == kind {
                return true;
            }
        }
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

#[expect(clippy::too_many_lines)]
async fn main_loop() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let config = global_config();

    let addr = SocketAddr::from((config.bind_addr, config.bind_port.get()));

    let listener = TcpListener::bind(addr).await.map_err(|err| {
        error!("Error binding on {addr}:  {err}");
        err
    })?;
    info!("Listening on http://{addr}");

    /* Set a process wide default crypto provider. */
    //let _ = rustls::crypto::ring::default_provider().install_default();
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let tls_cfg = rustls::ClientConfig::builder()
        .with_native_roots()?
        .with_no_client_auth();
    let https_connector = hyper_rustls::HttpsConnectorBuilder::new()
        .with_tls_config(tls_cfg)
        .https_or_http()
        .enable_http1()
        .build();

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
            error!("Error creating database:  {err}");
            err
        })?;

    database.init_tables().await.map_err(|err| {
        error!("Error initializing database:  {err}");
        err
    })?;

    let db_task_clone = database.clone();
    tokio::task::spawn(async move {
        if let Ok(cache_size) = task_cache_scan(db_task_clone).await {
            let rd = RUNTIMEDETAILS.get().expect("global set in main()");

            {
                let mut mg = rd.cache_size.lock().expect("Other users should not panic");
                *mg = cache_size;
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

    let active_downloads = ActiveDownloads::new();

    let mut term_signal = tokio::signal::unix::signal(SignalKind::terminate())?;
    let mut usr1_signal = tokio::signal::unix::signal(SignalKind::user_defined1())?;

    let first_cleanup = tokio::time::Instant::now() + Duration::from_secs(60 * 60); /* 1h */
    let mut cleanup_interval =
        tokio::time::interval_at(first_cleanup, Duration::from_secs(24 * 60 * 60)); /* every 24h */

    loop {
        trace!(
            "Active downloads ({}):  {:?}",
            active_downloads.len(),
            active_downloads
        );

        let db = database.clone();
        let ht = https_client.clone();
        let ad = active_downloads.clone();

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
                tokio::task::spawn( async move {
                    if let Err(err) = task_cleanup(db, ht, ad).await {
                        error!("Error performing cleanup task:  {err}");
                    }
                });
                continue;
            },
            _ = usr1_signal.recv() => {
                info!("SIGUSR1 received, issuing cleanup...");
                cleanup_interval.reset();
                tokio::task::spawn( async move {
                    if let Err(err) = task_cleanup(db, ht, ad).await {
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

        tokio::task::spawn(async move {
            if let Err(err) = http1::Builder::new()
                .serve_connection(
                    TokioIo::new(stream),
                    service_fn(move |req| {
                        pre_process_client_request_wrapper(
                            client,
                            req,
                            State {
                                https_client: ht.clone(),
                                database: db.clone(),
                                active_downloads: ad.clone(),
                            },
                        )
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

#[derive(Parser)]
#[command(author, version, about)]
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
    cache_size: std::sync::Mutex<u64>,
}

static RUNTIMEDETAILS: OnceLock<RuntimeDetails> = OnceLock::new();
static LOGSTORE: OnceLock<LogStore> = OnceLock::new();

#[must_use]
fn global_config() -> &'static Config {
    &RUNTIMEDETAILS
        .get()
        .expect("Global was initialized in main()")
        .config
}

fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let args = Cli::parse();

    let (config, cgf_fallback) = Config::new(&args.config_path)?;

    let config_log_level = config.log_level;
    let config_logstore_capacity = config.logstore_capacity;

    RUNTIMEDETAILS
        .set(RuntimeDetails {
            start_time: time::OffsetDateTime::now_utc(),
            config,
            cache_size: std::sync::Mutex::new(0),
        })
        .expect("Initial set should succeed");

    let output_log_config = if args.skip_log_timestamp {
        ConfigBuilder::new()
            .set_time_level(LevelFilter::Off)
            .build()
    } else {
        simplelog::Config::default()
    };

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
        .expect("Initial set should succeed");

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
            "Default configuration file {} not found, using defaults",
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
