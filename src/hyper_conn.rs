use std::{
    convert::Infallible, error::Error as _, num::NonZero, os::unix::fs::MetadataExt as _,
    path::Path, path::PathBuf, pin::Pin, sync::Arc, task::Poll::Pending, task::Poll::Ready,
};

use bytes::Buf as _;
use futures_util::TryStreamExt as _;
use hashbrown::hash_map::EntryRef;
use http::{
    HeaderName, HeaderValue, Method, Request, Response, StatusCode, Uri,
    header::{
        ACCEPT, ACCEPT_RANGES, AGE, CACHE_CONTROL, CONNECTION, CONTENT_LENGTH, CONTENT_RANGE,
        CONTENT_TYPE, DATE, ETAG, HOST, IF_MODIFIED_SINCE, IF_NONE_MATCH, IF_RANGE, LAST_MODIFIED,
        LOCATION, RANGE, RETRY_AFTER, SERVER, USER_AGENT, VIA,
    },
    uri::Authority,
};
use http_body::{Body, Frame, SizeHint};
use http_body_util::{BodyExt as _, Empty, combinators::BoxBody};
use hyper::{body::Incoming, server::conn::http1, service::service_fn};
use hyper_util::{client::legacy::connect::HttpConnector, rt::tokio::TokioIo};
#[cfg(feature = "mmap")]
use memmap2::{Advice, MmapOptions};
use pin_project::{pin_project, pinned_drop};
use rand::distr::{Bernoulli, Distribution as _};
use tokio::io::{AsyncReadExt as _, AsyncSeekExt as _, AsyncWriteExt as _};
use tracing::{debug, error, info, trace, warn};

#[cfg(feature = "mmap")]
use crate::mmap_body::MmapBody;
use crate::{
    APP_NAME, APP_USER_AGENT, APP_VIA, AppState, ClientInfo, ContentLength, Never, ProxyCacheBody,
    SCHEME_CACHE, Scheme, SchemeKey, SchemeKeyRef, VOLATILE_CACHE_MAX_AGE,
    VOLATILE_UNKNOWN_CONTENT_LENGTH_UPPER,
    active_downloads::{AbortReason, ActiveDownloadStatus, InsertOutcome},
    cache_conditional::{self, CacheInfo},
    cache_layout::{self, CachedFlavor, ConnectionDetails, SUBDIR_TMP},
    cache_metadata::{self, UpstreamMetadata},
    cache_quota::QuotaExceeded,
    channel_body::{ChannelBody, ChannelBodyError},
    client_counter,
    config::HttpsUpgradeMode,
    content_type_for_cached_file,
    database_task::{
        DatabaseCommand, DbCmdDelivery, DbCmdDownload, DbCmdOrigin, send_db_command,
        send_db_command_nonblocking,
    },
    deb_mirror::Origin,
    error::{ErrorReport, MirrorDownloadRate, ProxyCacheError, UpstreamFetchError},
    full_body, global_cache_quota, global_config, global_verify_throttle,
    guards::{DownloadBarrier, InitBarrier},
    http_etag::{is_valid_etag, write_etag},
    http_last_modified::write_last_modified,
    http_range::{self, HttpDate, ParsedRange, format_http_date, http_parse_range},
    humanfmt::HumanFmt,
    integrity, limits, metrics,
    permitted_host_cache::{authorize_cache_access, is_host_allowed_cached},
    precise_instant::PreciseInstant,
    quick_response,
    rate_checked_body::{MaybeRated, RateCheckedBodyErr},
    rate_checker::RateCheckDirection,
    rate_log,
    request_dispatch::{DispatchOutcome, dispatch_request},
    static_assert,
    uncacheables::record_uncacheable,
    utils::{
        self, TempPath, hint_sequential_read, is_peer_disconnect, tokio_tempfile,
        touch_volatile_mtime,
    },
    warn_on_content_type_mismatch, warn_once, warn_once_or_debug, warn_once_or_info,
    web_interface::serve_web_interface,
    xattr_helpers,
};
#[cfg(feature = "tls_rustls")]
use hyper_rustls::HttpsConnector;
#[cfg(all(feature = "tls_hyper", not(feature = "tls_rustls")))]
use hyper_tls::HttpsConnector;

pub(crate) type HttpClient = hyper_util::client::legacy::Client<
    hyper_timeout::TimeoutConnector<HttpsConnector<HttpConnector>>,
    Empty<bytes::Bytes>,
>;

/// Box `Empty` into [`ProxyCacheBody::Boxed`].
fn empty_body() -> ProxyCacheBody {
    let body = Empty::new().map_err(|never| match never {});
    ProxyCacheBody::Boxed(BoxBody::new(body))
}

#[must_use]
fn is_io_timed_out_in_chain(err: &(dyn std::error::Error + 'static)) -> bool {
    let mut cur: Option<&(dyn std::error::Error + 'static)> = Some(err);
    while let Some(e) = cur {
        if let Some(io) = e.downcast_ref::<std::io::Error>()
            && io.kind() == std::io::ErrorKind::TimedOut
        {
            return true;
        }
        cur = e.source();
    }
    false
}

/// On success the request `Parts` are handed back alongside the response —
/// they were consumed by the request anyway, and returning them lets the
/// rare redirect-follow path rebuild a request without the caller cloning
/// the whole HeaderMap up front.
pub(crate) async fn request_with_retry(
    client: &HttpClient,
    request: Request<Empty<bytes::Bytes>>,
) -> Result<(Response<Incoming>, http::request::Parts), hyper_util::client::legacy::Error> {
    const MAX_ATTEMPTS: u32 = 10;
    // Auto-mode's HTTPS-upgrade revert branch only fires once `attempt`
    // has crossed this threshold; below it, transient connect errors
    // retry without reverting the scheme.
    const HTTPS_UPGRADE_REVERT_AFTER_ATTEMPTS: u32 = 2;
    // The Always-mode terminal-failure HTTPS_UPGRADE_FAILED bump below
    // (gated on `attempt > MAX_ATTEMPTS` with `https_upgrade_test` still
    // set) relies on the Auto-mode revert firing first. If MAX_ATTEMPTS
    // were ever <= HTTPS_UPGRADE_REVERT_AFTER_ATTEMPTS, Auto mode would
    // also fall through here with the flag set and bump HTTPS_UPGRADE_FAILED
    // instead of HTTPS_UPGRADE_REVERTED.
    static_assert!(MAX_ATTEMPTS > HTTPS_UPGRADE_REVERT_AFTER_ATTEMPTS);

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
            metrics::HTTPS_UPGRADE_ATTEMPTED.increment();
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
    ) -> Result<(Response<Incoming>, http::request::Parts), (hyper_util::client::legacy::Error, Uri)>
    {
        let mut attempt = 1;
        let mut sleep_prev = 0;
        let mut sleep_curr = 500;

        loop {
            let req_clone = Request::from_parts(parts.clone(), Empty::new());

            let _: Never = match client.request(req_clone).await {
                Ok(response) => {
                    if https_upgrade_test {
                        metrics::HTTPS_UPGRADE_SUCCEEDED.increment();
                    }
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
                                ventry.insert_entry_with_key(
                                    SchemeKey {
                                        host: key.host.to_owned(),
                                        port: key.port,
                                    },
                                    scheme,
                                );
                                debug!(
                                    "Added cached {scheme} scheme for host {auth}, original scheme was {orig_scheme:?}"
                                );
                            }
                        }
                    }
                    metrics::record_upstream_status(response.status());
                    return Ok((response, parts));
                }
                Err(err) if !err.is_connect() => {
                    if is_io_timed_out_in_chain(&err) {
                        metrics::HTTP_TIMEOUT_UPSTREAM_READ.increment();
                    }
                    metrics::UPSTREAM_HYPER_REQUEST_FAILED.increment();
                    if https_upgrade_test {
                        // Non-connect transport error (e.g. read timeout,
                        // request framing) terminates the request without
                        // retry. Count the upgrade attempt as failed so the
                        // ATTEMPTED == SUCCEEDED + REVERTED + FAILED identity
                        // holds.
                        metrics::HTTPS_UPGRADE_FAILED.increment();
                    }
                    warn_once_or_info!(
                        "Request of internal client to {} failed:  {}",
                        parts.uri,
                        ErrorReport(&err)
                    );
                    return Err((err, parts.uri));
                }
                Err(err) => {
                    if is_io_timed_out_in_chain(&err) {
                        metrics::HTTP_TIMEOUT_UPSTREAM_CONNECT.increment();
                    }
                    if attempt > HTTPS_UPGRADE_REVERT_AFTER_ATTEMPTS
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

                        metrics::HTTPS_UPGRADE_REVERTED.increment();
                        // reset https upgrade
                        let mut uri_parts = parts.uri.into_parts();
                        uri_parts.scheme.clone_from(&orig_scheme);
                        parts.uri = Uri::from_parts(uri_parts).expect("valid parts");
                        https_upgrade_test = false;
                        sleep_prev = 0;
                        sleep_curr = 500;
                        // The revert iteration is another upstream attempt
                        // even though the retry budget (`attempt`) is not
                        // consumed for it. Match the regular retry arm in
                        // counting it as a retry.
                        metrics::UPSTREAM_RETRIES.increment();
                        continue;
                    }

                    if attempt > MAX_ATTEMPTS {
                        metrics::UPSTREAM_HYPER_REQUEST_FAILED.increment();
                        if https_upgrade_test {
                            // Terminal connect failure with the upgrade flag
                            // still set: in Always mode the revert branch
                            // above is gated off, so the only outcome of an
                            // attempted upgrade is failure here. Keep the
                            // ATTEMPTED == SUCCEEDED + REVERTED + FAILED
                            // identity.
                            metrics::HTTPS_UPGRADE_FAILED.increment();
                        }
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
                                metrics::SCHEME_CACHE_REMOVED.increment();
                                debug!(
                                    "Removed cached scheme {scheme} for host {auth} after {attempt} connection attempts, original scheme was {orig_scheme:?}"
                                );
                            }
                        }

                        // Single WARN authority for upstream-fetch failures: the
                        // non-connect arm above already warns; mirror it here so a
                        // connect-exhaustion terminal is logged once too (callers no
                        // longer re-warn).
                        warn_once_or_info!(
                            "Request of internal client to {} failed:  {}",
                            parts.uri,
                            ErrorReport(&err)
                        );

                        return Err((err, parts.uri));
                    }

                    debug!(
                        "Failed to connect to {} after {attempt} connection attempts, will retry in {sleep_curr} ms:  {}",
                        parts.uri,
                        ErrorReport(&err)
                    );

                    attempt += 1;
                    metrics::UPSTREAM_RETRIES.increment();

                    tokio::time::sleep(std::time::Duration::from_millis(sleep_curr)).await;
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
                // inner_loop already logged the transport error at WARN; keep this
                // background-task framing at DEBUG so request_with_retry stays the
                // single WARN authority (no cold-start double-warn).
                debug!(
                    "Failed to initialize scheme cache for host {} in background task:  {}",
                    err.1
                        .authority()
                        .expect("authority exists in case of https upgrade test"),
                    ErrorReport(&err.0)
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

/// Synthetic `502 Bad Gateway` for an upstream-fetch failure, carrying the real
/// transport reason as an `http::Extensions` value so an internal caller (cleanup)
/// can recover it instead of seeing only the laundered status. Real clients ignore
/// the extension (it is never serialised to the wire). The throw site does NOT log;
/// `request_with_retry` is the single WARN authority for upstream-fetch failures.
#[must_use]
fn upstream_error_response(err: &hyper_util::client::legacy::Error) -> Response<ProxyCacheBody> {
    let mut response = quick_response(StatusCode::BAD_GATEWAY, "Upstream Error");
    response.extensions_mut().insert(UpstreamFetchError {
        reason: ErrorReport(err).to_string(),
    });
    response
}

/* Adopted from http_body_util::StreamBody */
#[pin_project(PinnedDrop)]
struct DeliveryStreamBody<S, E> {
    #[pin]
    stream: S,
    start: PreciseInstant,
    size: u64,
    partial: bool,
    transferred_bytes: u64,
    conn_details: Option<ConnectionDetails>,
    /// Stringified error and peer-disconnect flag captured from the last stream error.
    error: Option<(String, bool)>,
    peer_disconnect_check: fn(&E) -> bool,
    _counter: client_counter::ClientDownload,
}

impl<S, E> DeliveryStreamBody<S, E> {
    #[must_use]
    fn new(
        stream: S,
        size: u64,
        partial: bool,
        conn_details: ConnectionDetails,
        peer_disconnect_check: fn(&E) -> bool,
    ) -> Self {
        metrics::REQUESTS_COPY.increment();
        Self {
            stream,
            start: PreciseInstant::now(),
            size,
            partial,
            transferred_bytes: 0,
            conn_details: Some(conn_details),
            error: None,
            peer_disconnect_check,
            _counter: client_counter::ClientDownload::new(),
        }
    }
}

impl<S, D, E: ToString> Body for DeliveryStreamBody<S, E>
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
                    Err(err) => {
                        let proj = self.project();
                        let is_disconnect = (proj.peer_disconnect_check)(err);
                        *proj.error = Some((err.to_string(), is_disconnect));
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
impl<S, E> PinnedDrop for DeliveryStreamBody<S, E> {
    fn drop(self: std::pin::Pin<&mut Self>) {
        let size = self.size;
        let partial = self.partial;
        let duration = self.start.elapsed();
        let transferred_bytes = self.transferred_bytes;
        metrics::BYTES_SERVED_COPY.increment_by(transferred_bytes);
        let project = self.project();
        let cd = project.conn_details.take().expect("Option is set in new()");
        let error = project.error.take();
        // Logging is synchronous and the DB enqueue has a sync fast path —
        // no per-request task spawn needed here.
        let aliased = match cd.aliased_host {
            Some(alias) => format!(" aliased to host {alias}"),
            None => String::new(),
        };
        let in_time = cd.request_received_at.elapsed();
        let volatile = if cd.cached_flavor == CachedFlavor::Volatile {
            "volatile "
        } else {
            ""
        };
        if transferred_bytes == size {
            metrics::SERVED_COPY.increment();
            metrics::SERVED_TOTAL.increment();
            info!(
                "Served cached {volatile}file {} from mirror {}{} for client {} in {} via stream ({})",
                cd.debname,
                cd.mirror,
                aliased,
                cd.client,
                HumanFmt::Time(in_time),
                rate_log::client_segment(size, duration),
            );
            let cmd = DatabaseCommand::Delivery(DbCmdDelivery {
                mirror: cd.mirror,
                debname: cd.debname,
                size,
                elapsed: duration,
                partial,
                client_ip: cd.client.ip(),
            });
            send_db_command_nonblocking(cmd);
        } else {
            let segment = rate_log::client_disconnect_segment(transferred_bytes, duration);
            let (reason, peer_disconnect) =
                error.unwrap_or_else(|| (String::from("unknown reason"), false));
            if peer_disconnect {
                metrics::CLIENT_DISCONNECTED_MID_BODY.increment();
                info!(
                    "Aborted serving cached {volatile}file {} from mirror {}{} for client {} in {} via stream ({segment}):  {reason}",
                    cd.debname,
                    cd.mirror,
                    aliased,
                    cd.client,
                    HumanFmt::Time(in_time),
                );
            } else {
                warn!(
                    "Aborted serving cached {volatile}file {} from mirror {}{} for client {} in {} via stream ({segment}):  {reason}",
                    cd.debname,
                    cd.mirror,
                    aliased,
                    cd.client,
                    HumanFmt::Time(in_time),
                );
            }
        }
    }
}

/// Body wrapper for the hyper simple-proxy path: counts data bytes into
/// [`metrics::BYTES_SERVED_PASSTHROUGH`] at poll time (hyper's body model
/// exposes no post-write hook). Splice/sendfile count post-write directly.
///
/// On Drop, bumps `SERVED_PASSTHROUGH` + `SERVED_TOTAL` iff the inner body
/// reached clean end-of-stream (`poll_frame` returned `Ready(None)`) without
/// ever surfacing an error — so aborted clients and errored deliveries do
/// not increment the served counter.  Also logs a per-request rate summary
/// (total in-time, upstream rate, client rate).
#[pin_project(PinnedDrop)]
struct PassthroughBody<B: Body> {
    #[pin]
    inner: B,
    end_of_stream: bool,
    // Sticky: set once `poll_frame` has yielded any `Err`, vetoing the
    // Drop-time `SERVED_*` credit even if a later poll reaches `Ready(None)`.
    errored: bool,
    transferred: u64,
    start: PreciseInstant,
    request_received_at: PreciseInstant,
    request_sent: PreciseInstant,
    host: String,
    path: String,
    client: ClientInfo,
}

impl<B: Body> PassthroughBody<B> {
    fn new(
        inner: B,
        request_received_at: PreciseInstant,
        request_sent: PreciseInstant,
        host: String,
        path: String,
        client: ClientInfo,
    ) -> Self {
        Self {
            inner,
            end_of_stream: false,
            errored: false,
            transferred: 0,
            start: PreciseInstant::now(),
            request_received_at,
            request_sent,
            host,
            path,
            client,
        }
    }
}

impl<B> Body for PassthroughBody<B>
where
    B: Body,
{
    type Data = B::Data;
    type Error = B::Error;

    #[inline]
    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.project();
        let result = this.inner.poll_frame(cx);
        match &result {
            Ready(Some(Ok(frame))) => {
                if let Some(data) = frame.data_ref() {
                    let n = data.remaining() as u64;
                    metrics::BYTES_SERVED_PASSTHROUGH.increment_by(n);
                    *this.transferred += n;
                }
            }
            Ready(None) => {
                *this.end_of_stream = true;
            }
            Ready(Some(Err(_))) => {
                *this.errored = true;
            }
            Pending => {}
        }
        result
    }

    #[inline]
    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }

    #[inline]
    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }
}

#[pinned_drop]
impl<B: Body> PinnedDrop for PassthroughBody<B> {
    fn drop(self: Pin<&mut Self>) {
        let transferred = self.transferred;
        let client_window = self.start.elapsed();
        let in_time = self.request_received_at.elapsed();
        let upstream_window = self.request_sent.elapsed();
        let end_of_stream = self.end_of_stream;
        let errored = self.errored;
        let this = self.project();
        let host = std::mem::take(this.host);
        let path = std::mem::take(this.path);
        let client = *this.client;
        if end_of_stream && !errored {
            metrics::SERVED_PASSTHROUGH.increment();
            metrics::SERVED_TOTAL.increment();
            info!(
                "simple proxy: passed through {path} from host {host} for client {client} in {} ({}, {})",
                HumanFmt::Time(in_time),
                rate_log::upstream_segment(transferred, upstream_window),
                rate_log::client_segment(transferred, client_window),
            );
        } else {
            info!(
                "simple proxy: aborted passthrough of {path} from host {host} for client {client} in {} ({})",
                HumanFmt::Time(in_time),
                rate_log::client_disconnect_segment(transferred, client_window),
            );
        }
    }
}

/// Body wrapper that holds a [`client_counter::ClientDownload`] for the lifetime
/// of the body so paths without their own counter (passthrough, upstream
/// error-body relay) still register in `ACTIVE_CLIENT_DOWNLOADS`. Forwards
/// `Body` methods unchanged.
#[pin_project]
struct ClientCountedBody<B: Body> {
    #[pin]
    inner: B,
    _counter: client_counter::ClientDownload,
}

impl<B: Body> ClientCountedBody<B> {
    fn new(inner: B) -> Self {
        Self {
            inner,
            _counter: client_counter::ClientDownload::new(),
        }
    }
}

impl<B> Body for ClientCountedBody<B>
where
    B: Body,
{
    type Data = B::Data;
    type Error = B::Error;

    #[inline]
    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        self.project().inner.poll_frame(cx)
    }

    #[inline]
    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }

    #[inline]
    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }
}

#[cfg(feature = "mmap")]
#[expect(
    clippy::too_many_arguments,
    clippy::inline_always,
    reason = "function has only 1 caller and is a tail call"
)]
#[inline(always)]
async fn serve_cached_file_mmap(
    conn_details: ConnectionDetails,
    file: tokio::fs::File,
    file_path: PathBuf,
    last_modified_str: std::sync::Arc<str>,
    age: u32,
    http_status: StatusCode,
    content_length: usize,
    content_start: u64,
    content_range: Option<String>,
    partial: bool,
    etag: Option<std::sync::Arc<str>>,
) -> Response<ProxyCacheBody> {
    trace!(
        "Using mmap(2) with start={content_start} and length={content_length} from content_range={content_range:?} for file `{}`",
        file_path.display()
    );

    // block_in_place, not spawn_blocking: mmap(2)/madvise(2) only build a
    // VMA (no I/O), so the blocking-pool dispatch/rendezvous would cost
    // more than the syscalls themselves — per-hit latency on every
    // mmap-served file.
    let Some(memory_map) = tokio::task::block_in_place(|| {
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
                "Failed to mmap downloaded file `{}`:  {}",
                file_path.display(),
                ErrorReport(err)
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
                "Failed to advise memory mapping of file `{}`:  {}",
                file_path.display(),
                ErrorReport(&err)
            );
        }

        Some(memory_map)
    }) else {
        metrics::CACHE_IO_FAILURE.increment();
        return quick_response(StatusCode::INTERNAL_SERVER_ERROR, "Cache Access Failure");
    };

    let content_type = content_type_for_cached_file(&conn_details.debname);

    let client = conn_details.client;

    let memory_body = MmapBody::new(memory_map, content_length, partial, conn_details);

    let config = global_config();

    let body = ProxyCacheBody::Mmap(
        MaybeRated::new(
            memory_body,
            config.min_download_rate,
            config.rate_check_timeframe,
            RateCheckDirection::Client,
        ),
        client,
    );

    // TODO: use become: https://github.com/rust-lang/rust/issues/112788
    serve_cached_file_response(
        http_status,
        last_modified_str,
        age,
        content_length as u64,
        content_type,
        body,
        content_range,
        etag,
    )
}

#[must_use]
async fn serve_unfinished_file(
    conn_details: ConnectionDetails,
    mut file: tokio::fs::File,
    file_path: PathBuf,
    status: Arc<tokio::sync::RwLock<ActiveDownloadStatus>>,
    content_length: ContentLength,
    mut receiver: tokio::sync::watch::Receiver<()>,
    upstream_metadata: &UpstreamMetadata,
) -> Response<ProxyCacheBody> {
    let config = global_config();

    let md = match file.metadata().await {
        Ok(data) if data.file_type().is_file() => data,
        Ok(_) => {
            metrics::CACHE_NON_REGULAR.increment();
            error!("Cache file `{}` is not a regular file", file_path.display());
            return quick_response(StatusCode::INTERNAL_SERVER_ERROR, "Cache Access Failure");
        }
        Err(err) => {
            metrics::CACHE_IO_FAILURE.increment();
            error!(
                "Failed to get metadata of file `{}`:  {}",
                file_path.display(),
                ErrorReport(&err)
            );
            return quick_response(StatusCode::INTERNAL_SERVER_ERROR, "Cache Access Failure");
        }
    };

    let cache_conditional::CacheInfo {
        file_etag,
        last_modified_str,
        age,
        last_modified_for_ims: _,
    } = CacheInfo::with_meta(&md, upstream_metadata);

    let content_type = content_type_for_cached_file(&conn_details.debname);
    let (tx, rx) = tokio::sync::mpsc::channel(64);

    tokio::task::spawn(async move {
        let start = PreciseInstant::now();
        debug!(
            "Starting stream task for downloading file `{}` from mirror {} with length {content_length:?} for client {}...",
            file_path.display(),
            conn_details.mirror,
            conn_details.client
        );

        let counter = client_counter::ClientDownload::new();

        let mut finished = false;
        let mut bytes = 0;
        let mut client_disconnected = false;
        let buf_size = config.buffer_size;

        // Late-joiner reads of an in-progress download are still sequential —
        // hint readahead before the streaming loop starts.  The final size
        // is unknown (file still growing), so always hint.
        hint_sequential_read(&file, u64::MAX, &file_path);

        // No BufReader: every read below goes into a fresh BytesMut of the
        // same capacity, so tokio's BufReader would bypass its internal
        // buffer on every read anyway — it only cost a dead allocation.
        'stream: loop {
            loop {
                let mut buf = bytes::BytesMut::with_capacity(buf_size);
                let ret = match file.read_buf(&mut buf).await {
                    Ok(0) => break, // EOF
                    Ok(r) => r,
                    Err(err) => {
                        metrics::CACHE_IO_FAILURE.increment();
                        error!(
                            "Failed to read from file `{}`:  {}",
                            file_path.display(),
                            ErrorReport(&err)
                        );
                        return;
                    }
                };

                let buf = buf.freeze();

                assert_eq!(buf.len(), ret, "buffer length must match read bytes");

                if let Err(tokio::sync::mpsc::error::SendError(_err)) = tx.send(Ok(buf)).await {
                    client_disconnected = true;
                    break 'stream;
                }

                bytes += ret as u64;
            }

            if finished {
                break;
            }

            if let Err(tokio::sync::watch::error::RecvError { .. }) = receiver.changed().await {
                /* sender closed, either download finished or aborted */
                let st = status.read().await;
                let _: Never = match *st {
                    // Verifying: writer has written all bytes and is hashing on
                    // a blocking thread. The open file handle stays valid
                    // across the upcoming rename, so drain like Finished.
                    ActiveDownloadStatus::Finished { .. }
                    | ActiveDownloadStatus::Verifying { .. } => {
                        drop(st);
                        finished = true;
                        continue;
                    }
                    ActiveDownloadStatus::Aborted(ref err) => {
                        match err {
                            AbortReason::MirrorDownloadRate(mdr) => {
                                let mdr = (*mdr).clone();
                                drop(st);
                                if tx
                                    .send(Err(ChannelBodyError::MirrorDownloadRate(mdr)))
                                    .await
                                    .is_err()
                                {
                                    // receiver gone, nothing to recover
                                }
                            }
                            AbortReason::AlreadyLoggedJustFail => {
                                drop(st);
                                // Reason already logged
                                debug!(
                                    "Download of file `{}` aborted, cancelling stream",
                                    file_path.display()
                                );
                            }
                        }

                        return;
                    }
                    ActiveDownloadStatus::Init(_) | ActiveDownloadStatus::Download { .. } => {
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
        drop(file);
        drop(receiver);
        drop(status);
        drop(tx);
        drop(counter);

        let elapsed = start.elapsed();
        let in_time = conn_details.request_received_at.elapsed();
        let volatile = if conn_details.cached_flavor == CachedFlavor::Volatile {
            "volatile "
        } else {
            ""
        };
        let aliased = match conn_details.aliased_host {
            Some(alias) => format!(" aliased to host {alias}"),
            None => String::new(),
        };
        if client_disconnected {
            info!(
                "Aborted serving downloading {volatile}file {} from mirror {}{aliased} for joining client {} in {} via channel ({})",
                conn_details.debname,
                conn_details.mirror,
                conn_details.client,
                HumanFmt::Time(in_time),
                rate_log::client_disconnect_segment(bytes, elapsed),
            );
        } else {
            info!(
                "Served downloading {volatile}file {} from mirror {}{aliased} for joining client {} in {} via channel ({})",
                conn_details.debname,
                conn_details.mirror,
                conn_details.client,
                HumanFmt::Time(in_time),
                rate_log::client_segment(bytes, elapsed),
            );
            let cmd = DatabaseCommand::Delivery(DbCmdDelivery {
                mirror: conn_details.mirror,
                debname: conn_details.debname,
                size: bytes,
                elapsed,
                partial: false,
                client_ip: conn_details.client.ip(),
            });
            send_db_command(cmd).await;
        }
    });

    let mut response_builder = Response::builder()
        .status(StatusCode::OK)
        .header(DATE, &*format_http_date())
        .header(VIA, APP_VIA)
        .header(CONNECTION, "keep-alive")
        .header(CONTENT_TYPE, content_type)
        .header(ACCEPT_RANGES, "bytes")
        .header(
            LAST_MODIFIED,
            HeaderValue::try_from(&*last_modified_str).expect("Http datetime is valid"),
        )
        .header(AGE, HeaderValue::from(age));

    if let Some(etag) = file_etag {
        response_builder = response_builder.header(
            ETAG,
            HeaderValue::try_from(&*etag).expect("ETag is validated before passing"),
        );
    }

    if let ContentLength::Exact(size) = content_length {
        response_builder = response_builder.header(CONTENT_LENGTH, HeaderValue::from(size.get()));
    }

    metrics::REQUESTS_CHANNEL.increment();
    let channel_body = ChannelBody::new(rx, content_length);

    let rated = MaybeRated::new(
        channel_body,
        config.min_download_rate,
        config.rate_check_timeframe,
        RateCheckDirection::Client,
    );

    let body = ProxyCacheBody::Boxed(BoxBody::new(rated.map_err(move |err| match *err {
        RateCheckedBodyErr::RateTimeout(error) => Box::new(ProxyCacheError::ClientDownloadRate {
            error,
            client: conn_details.client,
        }),
        RateCheckedBodyErr::Inner(ierr) => ierr,
    })));

    let response = response_builder.body(body).expect("HTTP response is valid");

    trace!("Outgoing response: {response:?}");

    response
}

/// A wrapper around [`UpstreamMetadata`] that supports borrowed and
/// shared references.
enum UpstreamMetadataView<'a> {
    Borrowed(&'a UpstreamMetadata),
    Arc(Arc<UpstreamMetadata>),
}

impl std::ops::Deref for UpstreamMetadataView<'_> {
    type Target = UpstreamMetadata;

    fn deref(&self) -> &Self::Target {
        match self {
            Self::Borrowed(meta) => meta,
            Self::Arc(meta) => meta,
        }
    }
}

#[must_use]
async fn serve_cached_file(
    conn_details: ConnectionDetails,
    req: &Request<Empty<()>>,
    file: tokio::fs::File,
    file_path: PathBuf,
    prefetched_upstream_metadata: Option<&UpstreamMetadata>,
    prefetched_local_metadata: Option<std::fs::Metadata>,
) -> Response<ProxyCacheBody> {
    let aliased = match conn_details.aliased_host {
        Some(alias) => format!(" aliased to host {alias}"),
        None => String::new(),
    };

    let mdata = match prefetched_local_metadata {
        Some(m) => {
            debug_assert!(
                m.file_type().is_file(),
                "prefetched_local_metadata must be a regular file; caller is responsible for the type check"
            );
            m
        }
        None => match file.metadata().await {
            Ok(m) if m.file_type().is_file() => m,
            Ok(_) => {
                metrics::CACHE_NON_REGULAR.increment();
                error!("Cache file `{}` is not a regular file", file_path.display());
                return quick_response(StatusCode::INTERNAL_SERVER_ERROR, "Cache Access Failure");
            }
            Err(err) => {
                metrics::CACHE_IO_FAILURE.increment();
                error!(
                    "Failed to get metadata of cached file `{}`:  {}",
                    file_path.display(),
                    ErrorReport(&err)
                );
                return quick_response(StatusCode::INTERNAL_SERVER_ERROR, "Cache Access Failure");
            }
        },
    };

    let file_size = mdata.len();

    let cache_key = cache_metadata::CacheMetadataKeyRef::new(
        &conn_details.mirror,
        &conn_details.debname,
        conn_details.layout,
    );

    // Caller pre-resolves on the stale-volatile revalidation path;
    // otherwise fall back to the post-flight cache (lazy-loads xattr on miss).
    let resolved_meta = match prefetched_upstream_metadata {
        Some(meta) => UpstreamMetadataView::Borrowed(meta),
        None => UpstreamMetadataView::Arc(
            cache_metadata::store().resolve(&cache_key, &file, &file_path),
        ),
    };

    let if_none_match_str = match req.headers().get(IF_NONE_MATCH) {
        Some(v) => {
            if let Ok(s) = v.to_str() {
                Some(s)
            } else {
                warn_once!(
                    "Client {} sent an invalid If-None-Match header: {v:?}",
                    conn_details.client
                );
                None
            }
        }
        None => None,
    };
    let if_modified_since_str = match req.headers().get(IF_MODIFIED_SINCE) {
        Some(v) => {
            if let Ok(s) = v.to_str() {
                Some(s)
            } else {
                warn_once!(
                    "Client {} sent an invalid If-Modified-Since header: {v:?}",
                    conn_details.client
                );
                None
            }
        }
        None => None,
    };

    let cache_info = CacheInfo::with_meta(&mdata, &resolved_meta);
    let serve_304 = cache_info.decide_serve_304(if_none_match_str, if_modified_since_str);

    let cache_conditional::CacheInfo {
        file_etag,
        last_modified_for_ims,
        last_modified_str,
        age,
    } = cache_info;

    if serve_304 {
        info!(
            "Serving 304 Not Modified for cached file {} from mirror {}{} for client {} via hyper",
            conn_details.debname, conn_details.mirror, aliased, conn_details.client
        );

        let mut builder = Response::builder()
            .status(StatusCode::NOT_MODIFIED)
            .header(DATE, &*format_http_date())
            .header(VIA, APP_VIA)
            .header(CONNECTION, "keep-alive")
            .header(
                LAST_MODIFIED,
                HeaderValue::try_from(&*last_modified_str).expect("HTTP date is valid"),
            )
            .header(AGE, HeaderValue::from(age));

        if let Some(etag) = file_etag {
            builder = builder.header(
                ETAG,
                HeaderValue::try_from(&*etag).expect("ETag is validated by read_etag"),
            );
        }

        let response = builder.body(empty_body()).expect("HTTP response is valid");

        trace!("Outgoing response: {response:?}");

        return response;
    }

    let (http_status, content_start, content_length, content_range, partial) =
        if let Some(range) = req.headers().get(RANGE).and_then(|val| val.to_str().ok()) {
            let if_range = req
                .headers()
                .get(IF_RANGE)
                .and_then(|val| val.to_str().ok());
            match http_parse_range(
                range,
                if_range,
                file_size,
                last_modified_for_ims,
                file_etag.as_deref(),
            ) {
                ParsedRange::Satisfiable(content_range, start, content_length) => (
                    StatusCode::PARTIAL_CONTENT,
                    start,
                    content_length,
                    Some(content_range),
                    true,
                ),
                ParsedRange::NotSatisfiable => {
                    return Response::builder()
                        .status(StatusCode::RANGE_NOT_SATISFIABLE)
                        .header(SERVER, APP_NAME)
                        .header(VIA, APP_VIA)
                        .header(DATE, &*format_http_date())
                        .header(CONNECTION, "keep-alive")
                        .header(
                            CONTENT_RANGE,
                            HeaderValue::try_from(format!("bytes */{file_size}"))
                                .expect("content range is valid"),
                        )
                        .body(empty_body())
                        .expect("HTTP response is valid");
                }
                ParsedRange::Invalid | ParsedRange::IfRangeFailed => {
                    (StatusCode::OK, 0, file_size, None, false)
                }
            }
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

        debug!(
            "Serving cached file {} from mirror {}{} for client {} via mmap...",
            conn_details.debname, conn_details.mirror, aliased, conn_details.client
        );

        // mmap path uses madvise(SEQUENTIAL) on the mapping itself, so no
        // posix_fadvise is needed here.

        // TODO: use become: https://github.com/rust-lang/rust/issues/112788
        return serve_cached_file_mmap(
            conn_details,
            file,
            file_path,
            last_modified_str,
            age,
            http_status,
            mmap_content_length,
            content_start,
            content_range,
            partial,
            file_etag,
        )
        .await;
    }

    // Buf path streams the file straight through; let the kernel grow its
    // readahead window accordingly.
    hint_sequential_read(&file, content_length, &file_path);

    debug!(
        "Serving cached file {} from mirror {}{} for client {} via stream...",
        conn_details.debname, conn_details.mirror, aliased, conn_details.client
    );

    // TODO: use become: https://github.com/rust-lang/rust/issues/112788
    serve_cached_file_buf(
        conn_details,
        file,
        file_path,
        file_size,
        last_modified_str,
        age,
        http_status,
        content_length,
        content_start,
        content_range,
        partial,
        file_etag,
    )
    .await
}

#[expect(
    clippy::too_many_arguments,
    clippy::inline_always,
    reason = "function has only 1 caller and is a tail call"
)]
#[inline(always)]
async fn serve_cached_file_buf(
    conn_details: ConnectionDetails,
    mut file: tokio::fs::File,
    file_path: PathBuf,
    file_size: u64,
    last_modified_str: std::sync::Arc<str>,
    age: u32,
    http_status: StatusCode,
    content_length: u64,
    start: u64,
    content_range: Option<String>,
    partial: bool,
    etag: Option<std::sync::Arc<str>>,
) -> Response<ProxyCacheBody> {
    debug_assert!(
        start + content_length <= file_size,
        "range {start}+{content_length} must not exceed file size {file_size}"
    );

    let config = global_config();
    let client = conn_details.client;

    if let Err(err) = file.seek(std::io::SeekFrom::Start(start)).await {
        metrics::CACHE_IO_FAILURE.increment();
        error!(
            "Error seeking cached file `{}` to {start}/{file_size}:  {}",
            file_path.display(),
            crate::error::ErrorReport(&err)
        );
        return quick_response(StatusCode::INTERNAL_SERVER_ERROR, "Cache Access Failure");
    }

    let content_type = content_type_for_cached_file(&conn_details.debname);

    // Bound the reader to the (possibly range-trimmed) content length,
    // mirroring the mmap path: an unbounded stream over-reads past a closed
    // range's end, and the surplus makes DeliveryStreamBody's Drop
    // accounting see transferred != size — logging a spurious "Aborted
    // serving" warn and skipping the SERVED_* metrics and delivery DB row
    // for a request that was actually served fully.
    let reader_stream = tokio_util::io::ReaderStream::with_capacity(
        tokio::io::AsyncReadExt::take(file, content_length),
        config.buffer_size,
    );

    let delivery_body = DeliveryStreamBody::new(
        reader_stream.map_ok(Frame::data),
        content_length,
        partial,
        conn_details,
        is_peer_disconnect,
    );

    let rated = MaybeRated::new(
        delivery_body,
        config.min_download_rate,
        config.rate_check_timeframe,
        RateCheckDirection::Client,
    )
    .map_err(move |err| match *err {
        RateCheckedBodyErr::RateTimeout(error) => {
            Box::new(ProxyCacheError::ClientDownloadRate { error, client })
        }
        RateCheckedBodyErr::Inner(ierr) => ierr.into(),
    });

    let body = ProxyCacheBody::Boxed(BoxBody::new(rated));

    // TODO: use become: https://github.com/rust-lang/rust/issues/112788
    serve_cached_file_response(
        http_status,
        last_modified_str,
        age,
        content_length,
        content_type,
        body,
        content_range,
        etag,
    )
}

#[expect(
    clippy::too_many_arguments,
    reason = "shared response builder for serve_cached_file_mmap and serve_cached_file_buf; is always called as a tail call"
)]
fn serve_cached_file_response(
    http_status: StatusCode,
    last_modified_str: std::sync::Arc<str>,
    age: u32,
    content_length: u64,
    content_type: &'static str,
    body: ProxyCacheBody,
    content_range: Option<String>,
    etag: Option<std::sync::Arc<str>>,
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

    let mut response_builder = Response::builder()
        .status(http_status)
        .header(DATE, &*format_http_date())
        .header(VIA, APP_VIA)
        .header(CONNECTION, "keep-alive")
        .header(CONTENT_LENGTH, HeaderValue::from(content_length))
        .header(CONTENT_TYPE, content_type)
        .header(
            LAST_MODIFIED,
            HeaderValue::try_from(&*last_modified_str).expect("date string is valid"),
        )
        .header(ACCEPT_RANGES, "bytes")
        .header(AGE, HeaderValue::from(age));

    if let Some(ct) = content_range {
        response_builder = response_builder.header(
            CONTENT_RANGE,
            HeaderValue::try_from(ct).expect("content range string is valid"),
        );
    }

    if let Some(etag) = etag {
        response_builder = response_builder.header(
            ETAG,
            HeaderValue::try_from(&*etag).expect("ETag is validated by read_etag"),
        );
    }

    let response = response_builder.body(body).expect("HTTP response is valid");

    trace!("Outgoing response of cached file: {response:?}");

    response
}

#[must_use]
async fn serve_downloading_file(
    conn_details: ConnectionDetails,
    req: Request<Empty<()>>,
    status: Arc<tokio::sync::RwLock<ActiveDownloadStatus>>,
    prefetched_upstream_metadata: Option<&UpstreamMetadata>,
) -> Response<ProxyCacheBody> {
    let mut init_waited = false;

    loop {
        let st = status.read().await;

        match &*st {
            ActiveDownloadStatus::Aborted(err) => {
                let (status_code, msg) = match err {
                    AbortReason::MirrorDownloadRate(_) => {
                        (StatusCode::GATEWAY_TIMEOUT, "Upstream Download Timeout")
                    }
                    AbortReason::AlreadyLoggedJustFail => {
                        (StatusCode::INTERNAL_SERVER_ERROR, "Download Aborted")
                    }
                };
                drop(st);
                drop(status);
                return quick_response(status_code, msg);
            }
            ActiveDownloadStatus::Init(init_rx) => {
                let mut init_rx = init_rx.clone();
                drop(st);

                debug_assert!(
                    !init_waited,
                    "state should change once a ping is received or the downloading task dropped the sender"
                );
                if init_waited {
                    error!(
                        "Download state still Init after waiting for download of {} from mirror {}",
                        conn_details.debname, conn_details.mirror
                    );
                    return quick_response(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "Download State Corrupted",
                    );
                }

                // Either the state changed manually by the downloading task,
                // or the downloading task just dropped the sender.
                if let Err(_err @ tokio::sync::watch::error::RecvError { .. }) =
                    init_rx.changed().await
                {}
                init_waited = true;
            }
            ActiveDownloadStatus::Finished { path, meta } => {
                let path_clone = path.clone();
                let prefetched_upstream_metadata = if let Some(meta) = prefetched_upstream_metadata
                {
                    Some(UpstreamMetadataView::Borrowed(meta))
                } else {
                    meta.as_ref()
                        .map(|meta| UpstreamMetadataView::Arc(Arc::clone(meta)))
                };
                drop(st);
                drop(status);
                let file = match tokio::fs::File::options()
                    .read(true)
                    .custom_flags(nix::libc::O_NOFOLLOW)
                    .open(&path_clone)
                    .await
                {
                    Ok(f) => f,
                    Err(err) => {
                        metrics::CACHE_IO_FAILURE.increment();
                        error!(
                            "Failed to open downloaded file `{}`:  {}",
                            path_clone.display(),
                            ErrorReport(&err)
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
                    file,
                    path_clone,
                    prefetched_upstream_metadata.as_deref(),
                    None,
                )
                .await;
            }
            ActiveDownloadStatus::Verifying {
                path,
                content_length: _,
                meta,
            } => {
                // Writer has finished writing all bytes; the file is being
                // hashed and will be renamed to its dest path. Open the
                // partial path now — the inode stays valid across the
                // upcoming rename. On the rare ENOENT race (open after the
                // rename completes but before the status flip lands), re-loop
                // and pick up the Finished state with the new path.
                let path_clone = path.clone();
                let prefetched_upstream_metadata = if let Some(meta) = prefetched_upstream_metadata
                {
                    Some(UpstreamMetadataView::Borrowed(meta))
                } else {
                    Some(UpstreamMetadataView::Arc(Arc::clone(meta)))
                };
                drop(st);
                let file = match tokio::fs::File::options()
                    .read(true)
                    .custom_flags(nix::libc::O_NOFOLLOW)
                    .open(&path_clone)
                    .await
                {
                    Ok(f) => f,
                    Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                        // Lost the rename race; re-read status.
                        continue;
                    }
                    Err(err) => {
                        metrics::CACHE_IO_FAILURE.increment();
                        error!(
                            "Failed to open verifying file `{}`:  {}",
                            path_clone.display(),
                            ErrorReport(&err)
                        );
                        return quick_response(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "Cache Access Failure",
                        );
                    }
                };
                drop(status);

                return serve_cached_file(
                    conn_details,
                    &req,
                    file,
                    path_clone,
                    prefetched_upstream_metadata.as_deref(),
                    None,
                )
                .await;
            }
            ActiveDownloadStatus::Download {
                path,
                content_length,
                rx: receiver,
                meta,
            } => {
                // Cannot use mmap(2) since the file is not yet completely written
                let file = match tokio::fs::File::options()
                    .read(true)
                    .custom_flags(nix::libc::O_NOFOLLOW)
                    .open(&path)
                    .await
                {
                    Ok(f) => f,
                    Err(err) => {
                        metrics::CACHE_IO_FAILURE.increment();
                        error!(
                            "Failed to open downloading file `{}`:  {}",
                            path.display(),
                            ErrorReport(&err)
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
                let upstream_metadata = Arc::clone(meta);
                drop(st);

                return serve_unfinished_file(
                    conn_details,
                    file,
                    path_clone,
                    status,
                    content_length_copy,
                    receiver_clone,
                    &upstream_metadata,
                )
                .await;
            }
        }
    }
}

enum CacheFileStat {
    Volatile {
        file: tokio::fs::File,
        file_path: PathBuf,
        local_modification_time: HttpDate,
        /// Existing on-disk size at the time `serve_volatile_file` opened the
        /// file.  Plumbed through so `serve_new_file` does not have to fetch
        /// the metadata a second time to size the quota reservation.
        prev_size: u64,
    },
    New,
}

#[must_use]
async fn serve_volatile_file(
    conn_details: ConnectionDetails,
    req: Request<Empty<()>>,
    file: tokio::fs::File,
    file_path: PathBuf,
    appstate: AppState,
) -> Response<ProxyCacheBody> {
    debug_assert_eq!(
        conn_details.cached_flavor,
        CachedFlavor::Volatile,
        "serve_volatile_file() assumes volatile flavor"
    );

    let mdata = match file.metadata().await {
        Ok(data) if data.file_type().is_file() => data,
        Ok(_) => {
            metrics::CACHE_NON_REGULAR.increment();
            error!("Cache file `{}` is not a regular file", file_path.display());
            return quick_response(StatusCode::INTERNAL_SERVER_ERROR, "Cache Access Failure");
        }
        Err(err) => {
            metrics::CACHE_IO_FAILURE.increment();
            error!(
                "Failed to get metadata of file `{}`:  {}",
                file_path.display(),
                ErrorReport(&err)
            );
            return quick_response(StatusCode::INTERNAL_SERVER_ERROR, "Cache Access Failure");
        }
    };
    let modified_system_time = mdata
        .modified()
        .expect("Platform should support modification timestamps via setup check");

    // Cache volatile files for short periods to reduce up-to-date requests.
    // Compute age from the raw SystemTime — HttpDate rounds sub-second mtimes
    // up to the next whole second, which would otherwise appear to be in the future.
    if let Ok(elapsed) = modified_system_time.elapsed() {
        if elapsed < VOLATILE_CACHE_MAX_AGE {
            debug!(
                "Volatile file `{}` age {} is within the {}s freshness window, serving cached version...",
                file_path.display(),
                HumanFmt::Time(elapsed),
                VOLATILE_CACHE_MAX_AGE.as_secs()
            );

            // Gated on `not(sendfile)`: when the sendfile backend is enabled,
            // it has already bumped VOLATILE_HIT before any fallback into hyper.
            // Cleanup-synthetic probes (task_cleanup's `.xz → .gz → raw` walk)
            // bypass sendfile and would otherwise inflate the user-facing
            // counter — exclude them.
            #[cfg(not(feature = "sendfile"))]
            if !conn_details.client.is_cleanup_synthetic() {
                metrics::VOLATILE_HIT.increment();
            }

            return serve_cached_file(conn_details, &req, file, file_path, None, Some(mdata)).await;
        }
    } else {
        warn!(
            "Volatile file `{}` was modified in the future, ignoring modification time",
            file_path.display()
        );
    }

    // Gated on `not(sendfile)`: when the sendfile backend is enabled, it has
    // already bumped VOLATILE_REFETCHED for this stale-volatile path before
    // any fallback into hyper. Cleanup-synthetic probes bypass sendfile and
    // are operator bookkeeping, not user traffic — exclude them so the
    // dashboard ratio reflects real client behavior only.
    #[cfg(not(feature = "sendfile"))]
    if !conn_details.client.is_cleanup_synthetic() {
        metrics::VOLATILE_REFETCHED.increment();
    }

    match appstate.active_downloads.insert(
        &conn_details.mirror,
        &conn_details.debname,
        conn_details.layout,
    ) {
        InsertOutcome::Joined { status } => {
            debug!(
                "Serving file {} already in cache / download from mirror {} for client {}...",
                conn_details.debname, conn_details.mirror, conn_details.client
            );
            serve_downloading_file(conn_details, req, status, None).await
        }
        InsertOutcome::Originator { init_tx, status } => {
            serve_new_file(
                conn_details,
                status,
                init_tx,
                req,
                CacheFileStat::Volatile {
                    file,
                    file_path,
                    local_modification_time: HttpDate::from(modified_system_time),
                    prev_size: mdata.size(),
                },
                appstate,
            )
            .await
        }
    }
}

#[expect(
    clippy::too_many_arguments,
    reason = "has only one caller and is task entrypoint"
)]
async fn download_file(
    conn_details: &ConnectionDetails,
    warn_on_override: bool,
    input: (Incoming, ContentLength),
    output: (tokio::fs::File, TempPath),
    mut dbarrier: DownloadBarrier,
    resume_offset: u64,
    request_sent: PreciseInstant,
    raw_uri_path: String,
) {
    let config = global_config();

    let start = PreciseInstant::now();

    debug!(
        "Starting download of file {} from mirror {} for client {}...",
        conn_details.debname, conn_details.mirror, conn_details.client
    );

    let body = input.0;
    let content_length = input.1;

    let mut bytes = 0;
    let buf_size = config.buffer_size;

    let mut writer = tokio::io::BufWriter::with_capacity(buf_size, output.0);
    let outpath = output.1;

    let mut body = MaybeRated::new(
        body,
        config.min_download_rate,
        config.rate_check_timeframe,
        RateCheckDirection::Upstream,
    );

    while let Some(next) = body.frame().await {
        let frame = match next {
            Ok(f) => f,
            Err(err) => {
                match *err {
                    RateCheckedBodyErr::RateTimeout(download_rate_err) => {
                        dbarrier
                            .abort_with_reason(AbortReason::MirrorDownloadRate(
                                MirrorDownloadRate {
                                    download_rate_err,
                                    mirror: conn_details.mirror.clone(),
                                    debname: conn_details.debname.clone(),
                                },
                            ))
                            .await;
                    }
                    RateCheckedBodyErr::Inner(ierr) => {
                        if is_io_timed_out_in_chain(&ierr) {
                            metrics::HTTP_TIMEOUT_UPSTREAM_READ.increment();
                        }
                        metrics::UPSTREAM_HYPER_BODY_ERR.increment();
                        warn_once_or_info!(
                            "Error extracting frame from body for file {} from mirror {} (time={}, size={}, upstream_rate={}):  {}",
                            conn_details.debname,
                            conn_details.mirror,
                            HumanFmt::Time(start.elapsed()),
                            HumanFmt::Size(bytes),
                            HumanFmt::Rate(bytes, start.elapsed()),
                            ErrorReport(&ierr),
                        );
                    }
                }

                // Flush buffered data so partial files retain what was received
                if let Err(err) = writer.flush().await {
                    metrics::CACHE_IO_FAILURE.increment();
                    error!(
                        "Failed to flush partial data to `{}`:  {}",
                        outpath.display(),
                        ErrorReport(&err)
                    );
                }
                return;
            }
        };
        if let Ok(mut chunk) = frame.into_data() {
            let chunk_len = chunk.len() as u64;
            bytes += chunk_len;
            metrics::BYTES_DOWNLOADED_UPSTREAM.increment_by(chunk_len);

            if bytes > content_length.upper().get() {
                metrics::UPSTREAM_PROTOCOL_VIOLATION.increment();
                warn_once_or_info!(
                    "More bytes received than expected for file {} from mirror {}: {bytes} vs {}",
                    conn_details.debname,
                    conn_details.mirror,
                    content_length.upper()
                );
                return;
            }

            if let Err(err) = writer.write_all_buf(&mut chunk).await {
                metrics::CACHE_IO_FAILURE.increment();
                error!(
                    "Failed to write to file `{}`:  {}",
                    outpath.display(),
                    ErrorReport(&err)
                );
                return;
            }

            dbarrier.ping_batched(chunk_len);
        }
    }

    match content_length {
        ContentLength::Exact(size) => {
            if bytes != size.get() {
                metrics::UPSTREAM_PROTOCOL_VIOLATION.increment();
                warn_once_or_info!(
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
                metrics::UPSTREAM_PROTOCOL_VIOLATION.increment();
                warn_once_or_info!(
                    "Content exceeded unknown-length limit: got {} but limit is {} for file {} from mirror {}",
                    bytes,
                    size.get(),
                    conn_details.debname,
                    conn_details.mirror
                );
                return;
            }
        }
    }

    let t_upstream_done = PreciseInstant::now();

    if let Err(err) = writer.flush().await {
        metrics::CACHE_IO_FAILURE.increment();
        error!(
            "Failed to flush file `{}`:  {}",
            outpath.display(),
            ErrorReport(&err)
        );
        return;
    }
    drop(writer);

    let dest_dir_path = conn_details.cache_dir_path();

    if let Err(err) = tokio::fs::create_dir_all(&dest_dir_path).await
        && err.kind() != tokio::io::ErrorKind::AlreadyExists
    {
        metrics::CACHE_IO_FAILURE.increment();
        error!(
            "Failed to create destination directory `{}`:  {}",
            dest_dir_path.display(),
            ErrorReport(&err)
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

    let total_bytes = resume_offset + bytes;

    {
        // Lock to block all downloading tasks, since the file from the
        // path of the downloading state is going to be moved.
        let rbarrier = dbarrier.begin_rename().await;

        /* Should only happen for concurrent downloads from aliased mirrors */
        if warn_on_override {
            match tokio::fs::try_exists(&dest_file_path).await {
                Ok(true) => {
                    warn!(
                        "Target file `{}` already exists, overwriting... (aliased={})",
                        dest_file_path.display(),
                        conn_details.aliased_host.is_some()
                    );
                }
                Ok(false) => {}
                Err(err) => {
                    warn!(
                        "Failed to check if `{}` exists:  {}",
                        dest_file_path.display(),
                        ErrorReport(&err)
                    );
                }
            }
        }

        let plan = integrity::RenamePlan {
            temp_path: outpath.to_path_buf(),
            dest_path: dest_file_path.clone(),
            bytes_received: total_bytes,
            resource_kind: conn_details.resource_kind,
            debname: conn_details.debname.clone(),
            host: conn_details.mirror.host().to_string(),
            mirror_path: conn_details.mirror.path().to_owned(),
            raw_uri_path,
        };
        match rbarrier.commit(plan).await {
            Ok(()) => {
                // The file was verified and renamed; defuse the temp guard.
                TempPath::defuse(outpath);
            }
            Err(err) => {
                // commit() already dropped the barrier (abort path) and logged
                // mismatch / verify-IO; rename failures are logged here. The
                // TempPath guard removes the temp file on drop. The client was
                // already served from the live stream.
                if let integrity::CommitError::Rename(io_err) = &err {
                    metrics::CACHE_IO_FAILURE.increment();
                    error!(
                        "Failed to rename file `{}` to `{}`:  {}",
                        outpath.display(),
                        dest_file_path.display(),
                        ErrorReport(io_err)
                    );
                }
                return;
            }
        }
    }

    let elapsed = start.elapsed();
    let in_time = conn_details.request_received_at.elapsed();
    let volatile = if conn_details.cached_flavor == CachedFlavor::Volatile {
        "volatile "
    } else {
        ""
    };
    info!(
        "Finished download of {volatile}file {} from mirror {} for client {} in {} ({}){}",
        conn_details.debname,
        conn_details.mirror,
        conn_details.client,
        HumanFmt::Time(in_time),
        rate_log::upstream_segment(bytes, t_upstream_done.duration_since(request_sent)),
        if resume_offset > 0 {
            format!(", resumed from {}", HumanFmt::Size(resume_offset))
        } else {
            String::new()
        },
    );

    let cmd = DatabaseCommand::Download(DbCmdDownload {
        mirror: conn_details.mirror.clone(),
        debname: conn_details.debname.clone(),
        size: total_bytes,
        elapsed,
        client_ip: conn_details.client.ip(),
    });
    send_db_command(cmd).await;
}

#[must_use]
async fn serve_new_file(
    conn_details: ConnectionDetails,
    status: Arc<tokio::sync::RwLock<ActiveDownloadStatus>>,
    init_tx: tokio::sync::watch::Sender<()>,
    req: Request<Empty<()>>,
    cfstate: CacheFileStat,
    appstate: AppState,
) -> Response<ProxyCacheBody> {
    // TODO: upstream constant
    const PROXY_CONNECTION: HeaderName = HeaderName::from_static("proxy-connection");

    #[must_use]
    fn build_fwd_request(
        uri: &Uri,
        host: &HeaderValue,
        cfstate: &CacheFileStat,
        volatile_etag: Option<&str>,
        resume_offset: u64,
        resume_if_range: Option<&str>,
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
            local_modification_time,
            prev_size: _,
        } = cfstate
        {
            let date_fmt = local_modification_time.format();

            let r = request.headers_mut().append(
                IF_MODIFIED_SINCE,
                HeaderValue::try_from(date_fmt).expect("HTTP datetime should be valid"),
            );
            assert!(!r, "header does not exist by previous construction");

            let r = request
                .headers_mut()
                .append(CACHE_CONTROL, HeaderValue::from_static("max-age=300"));
            assert!(!r, "header does not exist by previous construction");

            if let Some(etag) = volatile_etag {
                let r = request.headers_mut().append(
                    IF_NONE_MATCH,
                    HeaderValue::try_from(etag).expect("ETag is validated by read_etag"),
                );
                assert!(!r, "header does not exist by previous construction");
            }
        }

        if resume_offset > 0 {
            let r = request.headers_mut().append(
                RANGE,
                HeaderValue::try_from(format!("bytes={resume_offset}-"))
                    .expect("range value is valid"),
            );
            assert!(!r, "header does not exist by previous construction");

            if let Some(if_range) = resume_if_range {
                let r = request.headers_mut().append(
                    IF_RANGE,
                    HeaderValue::try_from(if_range).expect("If-Range value is valid"),
                );
                assert!(!r, "header does not exist by previous construction");
            }
        }

        request
    }

    let config = global_config();

    let ibarrier = InitBarrier::new(
        init_tx,
        &status,
        &appstate.active_downloads,
        &conn_details.mirror,
        conn_details.aliased_host,
        &conn_details.debname,
        conn_details.layout,
    );

    let (warn_on_override, prev_file_size) = match &cfstate {
        CacheFileStat::Volatile {
            file: _,
            file_path: _,
            local_modification_time: _,
            prev_size,
        } => (false, *prev_size),
        CacheFileStat::New => (true, 0),
    };

    let mut host = None;

    for (name, value) in req.headers() {
        match name {
            &USER_AGENT | &RANGE | &IF_RANGE | &ACCEPT | &IF_MODIFIED_SINCE | &CACHE_CONTROL
            | &CONNECTION => (),
            n if n == PROXY_CONNECTION => (),
            &HOST => host = Some(value),

            _ => {
                metrics::UNHANDLED_REQUEST_HEADERS.increment();
                warn_once_or_info!(
                    "Unhandled HTTP header `{name}` with value `{value:?}` in request from client {}",
                    conn_details.client
                );
            }
        }
    }
    // mark immutable
    let host = match host {
        Some(h) => h,
        None => {
            // RFC 3986 §3.2.2: IPv6 addresses must be bracketed in Host headers
            &HeaderValue::from_str(&conn_details.mirror.format_authority())
                .expect("connection host should be valid")
        }
    };

    let mut req_uri = std::borrow::Cow::Borrowed(req.uri());

    if let Some(max) = config.max_upstream_downloads
        && appstate.active_downloads.len() > max.get()
    {
        warn_once_or_info!(
            "Max upstream downloads ({max}) exceeded, rejecting request for {} from client {}",
            conn_details.debname,
            conn_details.client
        );
        metrics::UPSTREAM_DOWNLOAD_REJECTED_CAP.increment();
        return quick_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "Too many concurrent upstream downloads",
        );
    }

    // Cleanup probes bypass the throttle: they run once per 24h cycle and a
    // 503 would hard-fail the index-fetch cascade; their commit outcome
    // still records/clears throttle state.
    if !conn_details.client.is_cleanup_synthetic()
        && let Some(throttled) = global_verify_throttle().check(
            &conn_details.mirror,
            &conn_details.debname,
            conn_details.layout,
        )
    {
        warn_once_or_info!(
            "Rejecting request for {} from client {}: recently failed checksum verification ({} consecutive failures), retry in {}",
            conn_details.debname,
            conn_details.client,
            throttled.failures,
            HumanFmt::Time(throttled.remaining)
        );
        metrics::DOWNLOAD_REJECTED_VERIFY_THROTTLE.increment();
        let secs =
            u32::try_from(throttled.remaining.as_secs().saturating_add(1)).unwrap_or(u32::MAX);
        return Response::builder()
            .status(StatusCode::SERVICE_UNAVAILABLE)
            .header(SERVER, APP_NAME)
            .header(VIA, APP_VIA)
            .header(DATE, format_http_date())
            .header(CONNECTION, "keep-alive")
            .header(CONTENT_TYPE, "text/plain; charset=utf-8")
            .header(RETRY_AFTER, HeaderValue::from(secs))
            .body(full_body("Recently failed checksum verification"))
            .expect("Response is valid");
    }

    let prefetched_upstream_metadata = match &cfstate {
        CacheFileStat::Volatile {
            file,
            file_path,
            local_modification_time: _,
            prev_size: _,
        } => {
            let key = cache_metadata::CacheMetadataKeyRef::new(
                &conn_details.mirror,
                &conn_details.debname,
                conn_details.layout,
            );

            Some(cache_metadata::store().resolve(&key, file, file_path))
        }
        CacheFileStat::New => None,
    };
    let volatile_etag = prefetched_upstream_metadata
        .as_ref()
        .and_then(|m| m.etag.as_deref());

    // Check for a partial download file to resume (permanent files only).
    // Opens the file upfront (if it exists and is non-empty) to get size + mtime
    // from the same file descriptor, avoiding TOCTOU races between metadata() and open().
    // The guard uses keep_on_drop: true so the partial file survives transient
    // errors (e.g., upstream 5xx) and can be resumed on the next attempt.
    // `partial.discard_resume()` is used only when a stale partial must be
    // discarded (200 fallback from unsupported Range, 416, invalid Content-Range).
    let (mut resume_offset, mut resume_expected_total, resume_if_range, mut partial) =
        if conn_details.cached_flavor == CachedFlavor::Permanent
            && matches!(cfstate, CacheFileStat::New)
        {
            match utils::prepare_partial_resume(
                &ibarrier,
                &conn_details.debname,
                &conn_details.mirror,
                "",
            )
            .await
            {
                Ok(r) => (r.offset, r.expected_total, r.if_range, r.partial),
                Err((err, guard)) if err.kind() == std::io::ErrorKind::NotFound => {
                    (0, None, None, utils::PartialDownload::Fresh(guard))
                }
                Err((_err, guard)) => {
                    // Error already logged in `open_partial_file()`.
                    drop(guard);
                    return quick_response(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "Cache Access Failure",
                    );
                }
            }
        } else {
            (0, None, None, utils::PartialDownload::Volatile)
        };

    let fwd_request = build_fwd_request(
        &req_uri,
        host,
        &cfstate,
        volatile_etag,
        resume_offset,
        resume_if_range.as_deref(),
    );
    trace!("Forwarded request: {fwd_request:?}");

    let mut upstream_request_sent = PreciseInstant::now();
    let mut fwd_response = match request_with_retry(&appstate.https_client, fwd_request).await {
        Ok((r, _parts)) => r,
        Err(err) => return upstream_error_response(&err),
    };

    trace!("Forwarded response: {fwd_response:?}");

    if matches!(
        fwd_response.status(),
        StatusCode::MOVED_PERMANENTLY
            | StatusCode::FOUND
            | StatusCode::TEMPORARY_REDIRECT
            | StatusCode::PERMANENT_REDIRECT
    ) && let Some(moved_uri) = fwd_response
        .headers()
        .get(LOCATION)
        .and_then(|lc| lc.to_str().ok())
        .and_then(|lc_str| lc_str.parse::<hyper::Uri>().ok())
    {
        debug!("Requested URI: {}, Moved URI: {moved_uri:?}", req.uri());

        if moved_uri.scheme().is_some_and(|scheme| {
            *scheme == http::uri::Scheme::HTTP || *scheme == http::uri::Scheme::HTTPS
        }) && let Some(moved_auth) = moved_uri.authority()
            && is_host_allowed_cached(moved_auth.host())
        {
            // Derive the Host header from the redirect target so it matches
            // the URI we're actually sending the request to.
            let redirected_host = host_header_from_uri(moved_auth);

            req_uri = std::borrow::Cow::Owned(moved_uri);

            let redirected_request = build_fwd_request(
                &req_uri,
                &redirected_host,
                &cfstate,
                volatile_etag,
                resume_offset,
                resume_if_range.as_deref(),
            );

            trace!("Forwarded redirected request: {redirected_request:?}");

            upstream_request_sent = PreciseInstant::now();
            let redirected_response =
                match request_with_retry(&appstate.https_client, redirected_request).await {
                    Ok((r, _parts)) => r,
                    Err(err) => return upstream_error_response(&err),
                };

            trace!("Forwarded redirected response: {redirected_response:?}");

            fwd_response = redirected_response;
        } else if moved_uri.scheme().is_none_or(|scheme| {
            *scheme != http::uri::Scheme::HTTP && *scheme != http::uri::Scheme::HTTPS
        }) {
            debug!("Scheme of moved URI `{moved_uri:?}` not supported");
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
        local_modification_time: _,
        prev_size: _,
    } = cfstate
    {
        if fwd_response.status() == StatusCode::NOT_MODIFIED {
            // Skip the counter for cleanup-synthetic probes: they bypass
            // sendfile and never bump VOLATILE_REFETCHED in the default build,
            // so counting their 304s here would let the subset run ahead of
            // the parent.
            if !conn_details.client.is_cleanup_synthetic() {
                metrics::VOLATILE_REFETCHED_UPTODATE.increment();
            }
            file = touch_volatile_mtime(file, &file_path).await;

            ibarrier.finished(file_path.clone()).await;

            return serve_cached_file(
                conn_details,
                &req,
                file,
                file_path,
                prefetched_upstream_metadata.as_deref(),
                None,
            )
            .await;
        }

        // Only count "out of date" when upstream actually returned fresh
        // content (mirrors the splice path's non-200/non-206 passthrough in
        // `splice_proxy_drive`); a 4xx/5xx revalidation is not a fresh body.
        // Cleanup-synthetic probes bypass the parent counter and are excluded
        // for the same reason as the UPTODATE site above.
        let status = fwd_response.status();
        if (status == StatusCode::OK || status == StatusCode::PARTIAL_CONTENT)
            && !conn_details.client.is_cleanup_synthetic()
        {
            metrics::VOLATILE_REFETCHED_OUTOFDATE.increment();
        }
        debug!(
            "File `{}` did not revalidate (status={})",
            file_path.display(),
            fwd_response.status()
        );
    }

    // Handle resume: if we sent Range and got 200 (server ignores Range) or 416
    // (partial is stale), discard partial and start fresh.
    let needs_retry = if resume_offset > 0 && fwd_response.status() == StatusCode::OK {
        info!(
            "Server returned 200 instead of 206 for resume of {} from mirror {}, starting fresh",
            conn_details.debname, conn_details.mirror
        );
        partial.discard_resume().await;
        resume_offset = 0;
        resume_expected_total = None;
        false
    } else if resume_offset > 0 && fwd_response.status() == StatusCode::RANGE_NOT_SATISFIABLE {
        warn_once_or_info!(
            "Server returned 416 for resume of {} from mirror {} (partial {} bytes), discarding stale partial",
            conn_details.debname,
            conn_details.mirror,
            resume_offset
        );
        partial.discard_resume().await;
        resume_offset = 0;
        resume_expected_total = None;
        true
    } else if resume_offset > 0 && fwd_response.status() == StatusCode::PARTIAL_CONTENT {
        // Validate Content-Range before proceeding: if the server returned 206 but the
        // Content-Range doesn't match our resume offset or the total size changed
        // (e.g. file replaced upstream with a different size), discard the stale
        // partial and retry fresh — same pattern as 416 handling.
        // Only accept a 206 that delivers the full remainder (start == resume_offset
        // AND end == total - 1). Otherwise `body_content_length` computed from
        // `total - resume_offset` would not match the bytes on the wire and the
        // writer would hang or truncate.
        let content_range_valid = fwd_response
            .headers()
            .get(CONTENT_RANGE)
            .and_then(|hv| hv.to_str().ok())
            .and_then(http_range::parse_content_range)
            .is_some_and(|(start, end, total)| {
                start == resume_offset
                    && end.checked_add(1) == Some(total)
                    && resume_expected_total.is_none_or(|expected| expected == total)
            });

        if content_range_valid {
            false
        } else {
            warn_once_or_info!(
                "Invalid or mismatched Content-Range in 206 for {} from mirror {}, discarding partial and retrying fresh",
                conn_details.debname,
                conn_details.mirror
            );
            partial.discard_resume().await;
            resume_offset = 0;
            resume_expected_total = None;
            true
        }
    } else {
        false
    };

    if needs_retry {
        // Deliberately pass CacheFileStat::New here rather than the original
        // `cfstate` binding: at this point the partial file has been discarded
        // (and any prior cached data is being superseded), so from the
        // upstream's perspective this is a fresh unconditional fetch — no
        // If-Modified-Since, no If-None-Match, no Range.
        let retry_request =
            build_fwd_request(&req_uri, host, &CacheFileStat::New, volatile_etag, 0, None);

        upstream_request_sent = PreciseInstant::now();
        fwd_response = match request_with_retry(&appstate.https_client, retry_request).await {
            Ok((r, _parts)) => r,
            Err(err) => return upstream_error_response(&err),
        };
    }

    // Reject unsolicited 206: upstream returned partial content for a request
    // without Range. Treating it as a fresh 200 would write the partial bytes
    // into the cache at offset 0 and mark the file complete at the partial
    // length - a cache-poisoning vector.
    if resume_offset == 0 && fwd_response.status() == StatusCode::PARTIAL_CONTENT {
        metrics::UPSTREAM_PROTOCOL_VIOLATION.increment();
        metrics::UPSTREAM_UNSOLICITED_206.increment();
        warn_once_or_info!(
            "Upstream returned 206 Partial Content without a Range request for {} from mirror {}",
            conn_details.debname,
            conn_details.mirror
        );
        return quick_response(StatusCode::BAD_GATEWAY, "Unsolicited 206");
    }

    // Parse total file size and body content length for resume vs fresh downloads
    let (total_content_length, body_content_length) = if resume_offset > 0
        && fwd_response.status() == StatusCode::PARTIAL_CONTENT
    {
        // Parse Content-Range header for 206 responses
        let content_range = fwd_response
            .headers()
            .get(CONTENT_RANGE)
            .and_then(|hv| hv.to_str().ok())
            .and_then(http_range::parse_content_range);

        match content_range {
            Some((start, end, total))
                if start == resume_offset
                    && end.checked_add(1) == Some(total)
                    && resume_expected_total.is_none_or(|expected| expected == total) =>
            {
                let remaining = end - start + 1;
                // Cross-check declared Content-Length (if present) matches the range span.
                if let Some(cl) = fwd_response
                    .headers()
                    .get(http::header::CONTENT_LENGTH)
                    .and_then(|hv| hv.to_str().ok())
                    .and_then(|s| s.parse::<u64>().ok())
                    && cl != remaining
                {
                    metrics::UPSTREAM_PROTOCOL_VIOLATION.increment();
                    warn_once_or_info!(
                        "Content-Length {cl} disagrees with Content-Range span {remaining} for {} from mirror {}",
                        conn_details.debname,
                        conn_details.mirror
                    );
                    return quick_response(StatusCode::BAD_GATEWAY, "Inconsistent Content-Range");
                }
                let Some(total_nz) = NonZero::new(total) else {
                    metrics::UPSTREAM_PROTOCOL_VIOLATION.increment();
                    warn_once_or_info!(
                        "Content-Range total is zero for {} from mirror {}",
                        conn_details.debname,
                        conn_details.mirror
                    );
                    return quick_response(StatusCode::BAD_GATEWAY, "Invalid Content-Range");
                };

                if !limits::content_length_within_cap(
                    total_nz.get(),
                    global_config().max_object_size,
                ) {
                    metrics::DOWNLOAD_REJECTED_OVERSIZE.increment();
                    warn_once_or_info!(
                        "Upstream 206 declares total size {} for file {} from mirror {}, exceeding max_object_size",
                        total_nz.get(),
                        conn_details.debname,
                        conn_details.mirror
                    );
                    return quick_response(StatusCode::BAD_GATEWAY, "Upstream resource too large");
                }

                let Some(remaining_nz) = NonZero::new(remaining) else {
                    metrics::UPSTREAM_PROTOCOL_VIOLATION.increment();
                    // File is already complete — guard drops and cleans up partial
                    warn_once_or_info!(
                        "Partial file is already complete for {} from mirror {}",
                        conn_details.debname,
                        conn_details.mirror
                    );
                    return quick_response(StatusCode::BAD_GATEWAY, "No remaining bytes");
                };
                #[expect(clippy::cast_precision_loss, reason = "only for display purpose")]
                let remaining_percent = remaining as f32 / total as f32 * 100.0;
                info!(
                    "Resuming download of {} from mirror {} at {} ({} ({:.1}%) remaining of {} total)",
                    conn_details.debname,
                    conn_details.mirror,
                    HumanFmt::Size(resume_offset),
                    HumanFmt::Size(remaining),
                    remaining_percent,
                    HumanFmt::Size(total)
                );
                (
                    ContentLength::Exact(total_nz),
                    ContentLength::Exact(remaining_nz),
                )
            }
            // Content-Range mismatch or missing: should be handled by the
            // pre-check above (which discards partial and retries fresh).
            // Defensive fallback in case of unexpected state.
            _ => {
                metrics::UPSTREAM_PROTOCOL_VIOLATION.increment();
                warn_once_or_info!(
                    "Unexpected Content-Range state for 206 response of {} from mirror {}",
                    conn_details.debname,
                    conn_details.mirror
                );
                return quick_response(StatusCode::BAD_GATEWAY, "Unexpected Content-Range");
            }
        }
    } else {
        // Fresh download (including after fallback from failed resume)
        resume_offset = 0;

        if fwd_response.status() != StatusCode::OK {
            // Demote routine 4xx for cleanup-synthetic clients to DEBUG:
            // `try_fetch_packages_file` deliberately walks `.xz → .gz → raw`,
            // and on S3-hosted flat repos every miss surfaces as 403 (not
            // 404). At WARN that's three loud lines per cleanup cycle for
            // a benign probe sequence — the cleanup's own DEBUG line on
            // each miss is the operator-visible record.
            if fwd_response.status() == StatusCode::NOT_FOUND
                || conn_details.client.is_cleanup_synthetic()
            {
                debug!(
                    "Request for file {} from mirror {} with URI `{req_uri}` failed with code `{}`",
                    conn_details.debname,
                    conn_details.mirror,
                    fwd_response.status()
                );
            } else {
                warn_once_or_info!(
                    "Request for file {} from mirror {} with URI `{req_uri}` failed with code `{}`",
                    conn_details.debname,
                    conn_details.mirror,
                    fwd_response.status()
                );
            }

            // Cleanup probes read only the status; relaying the upstream error
            // body just makes the consumer drop it undrained (a spurious
            // "aborted passthrough" log), and these are not client passthroughs.
            if conn_details.client.is_cleanup_synthetic() {
                return quick_response(fwd_response.status(), "");
            }

            let (parts, body) = fwd_response.into_parts();

            metrics::REQUESTS_PASSTHROUGH.increment();
            let counted = ClientCountedBody::new(PassthroughBody::new(
                body,
                conn_details.request_received_at,
                upstream_request_sent,
                conn_details.mirror.format_authority().to_string(),
                req_uri.path().to_owned(),
                conn_details.client,
            ));

            let rated = MaybeRated::new(
                counted,
                config.min_download_rate,
                config.rate_check_timeframe,
                RateCheckDirection::Client,
            );

            let body = ProxyCacheBody::Boxed(BoxBody::new(rated.map_err(move |err| match *err {
                RateCheckedBodyErr::RateTimeout(error) => {
                    Box::new(ProxyCacheError::ClientDownloadRate {
                        error,
                        client: conn_details.client,
                    })
                }
                RateCheckedBodyErr::Inner(ierr) => ierr.into(),
            })));

            let mut response = Response::from_parts(parts, body);
            response
                .headers_mut()
                .append(VIA, HeaderValue::from_static(APP_VIA));

            trace!("Outgoing response: {response:?}");

            return response;
        }

        let cl = match fwd_response.headers().get(CONTENT_LENGTH).and_then(|hv| {
            hv.to_str()
                .ok()
                .and_then(|ct| ct.parse::<NonZero<u64>>().ok())
        }) {
            Some(size) => {
                if !limits::content_length_within_cap(size.get(), global_config().max_object_size) {
                    metrics::DOWNLOAD_REJECTED_OVERSIZE.increment();
                    warn_once_or_info!(
                        "Upstream declared Content-Length {} for file {} from mirror {}, exceeding max_object_size",
                        size.get(),
                        conn_details.debname,
                        conn_details.mirror
                    );
                    return quick_response(StatusCode::BAD_GATEWAY, "Upstream resource too large");
                }
                ContentLength::Exact(size)
            }
            None if conn_details.cached_flavor == CachedFlavor::Volatile => {
                ContentLength::Unknown(VOLATILE_UNKNOWN_CONTENT_LENGTH_UPPER)
            }
            None => {
                metrics::UPSTREAM_PROTOCOL_VIOLATION.increment();
                warn_once_or_info!(
                    "Could not extract content-length from header for file {} from mirror {}: {:?}",
                    conn_details.debname,
                    conn_details.mirror,
                    fwd_response.headers()
                );
                return quick_response(
                    StatusCode::BAD_GATEWAY,
                    "Upstream resource has no content length",
                );
            }
        };
        (cl, cl)
    };
    // mark immutable
    let resume_offset = resume_offset;

    debug_assert!(
        match (total_content_length, body_content_length) {
            (ContentLength::Exact(total), ContentLength::Exact(body)) =>
                resume_offset + body.get() == total.get(),
            _ => true,
        },
        "resume_offset ({resume_offset}) + body ({body_content_length}) must equal total ({total_content_length})"
    );

    let reservation = match global_cache_quota().try_acquire(
        total_content_length,
        prev_file_size,
        &conn_details.debname,
    ) {
        Ok(r) => Some(r),
        Err(QuotaExceeded) => {
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

    let upstream_last_modified: Option<String> = fwd_response
        .headers()
        .get(LAST_MODIFIED)
        .and_then(|hv| hv.to_str().ok())
        .filter(|lm| {
            if HttpDate::parse(lm).is_some() {
                true
            } else {
                warn_once_or_info!(
                    "Upstream mirror {} sent invalid Last-Modified for {}: {lm}",
                    conn_details.mirror,
                    conn_details.debname
                );
                false
            }
        })
        .map(String::from);

    let upstream_content_type: Option<&str> = fwd_response
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|hv| hv.to_str().ok());
    warn_on_content_type_mismatch(
        upstream_content_type,
        &conn_details.mirror,
        &conn_details.debname,
    );

    let (_parts, body) = fwd_response.into_parts();

    let filename = Path::new(&conn_details.debname);
    assert!(
        filename.is_relative(),
        "path construction must not contain absolute components"
    );

    // Create/open the output file: partial path for permanent files, random temp for volatile.
    // Defuse the guard once we take ownership of the partial path — from here on, the
    // download's own TempPath (keep_on_drop: true) manages the file lifetime.
    let (outfile, outpath) = match partial {
        utils::PartialDownload::Resumable { mut file, guard } => {
            // Resume: use the file already opened during the partial-file check.
            // The file handle has been held open since the check, so no TOCTOU race.
            // Verify the file size matches expectations (should always hold since
            // we've held the fd open, but check as defense-in-depth).
            let current_size = match file.seek(std::io::SeekFrom::End(0)).await {
                Ok(size) => size,
                Err(err) => {
                    metrics::CACHE_IO_FAILURE.increment();
                    error!(
                        "Failed to seek in partial file for `{}`:  {}",
                        conn_details.debname,
                        ErrorReport(&err)
                    );
                    return quick_response(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "Cache Access Failure",
                    );
                }
            };
            if current_size != resume_offset {
                error!(
                    "Partial file size {current_size} != expected {resume_offset} despite held fd, aborting resume"
                );
                return quick_response(StatusCode::INTERNAL_SERVER_ERROR, "Cache Access Failure");
            }
            (file, guard)
        }
        utils::PartialDownload::Fresh(guard) => {
            // Fresh permanent download: create at deterministic partial path
            match utils::create_partial_file(guard, 0o640).await {
                Ok((f, p)) => (f, p),
                Err((err, path)) => {
                    metrics::CACHE_IO_FAILURE.increment();
                    error!(
                        "Error creating partial file `{}`:  {}",
                        path.display(),
                        ErrorReport(&err)
                    );
                    return quick_response(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "Cache Access Failure",
                    );
                }
            }
        }
        utils::PartialDownload::Volatile => {
            // Volatile file: random temp file
            let tmppath: PathBuf = [&config.cache_directory, Path::new(SUBDIR_TMP), filename]
                .iter()
                .collect();
            match tokio_tempfile(&tmppath, 0o640).await {
                Ok((f, p)) => (f, p),
                Err(err) => {
                    metrics::CACHE_IO_FAILURE.increment();
                    error!(
                        "Error creating temporary file `{}`:  {}",
                        tmppath.display(),
                        ErrorReport(&err)
                    );
                    return quick_response(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "Cache Access Failure",
                    );
                }
            }
        }
    };

    // Write ETag xattr early so it survives partial downloads for resume
    if let Some(ref etag) = upstream_etag {
        write_etag(&outfile, &outpath, etag);
    }
    // Write upstream Last-Modified xattr early so it survives partial downloads
    if let Some(ref lm) = upstream_last_modified {
        write_last_modified(&outfile, &outpath, lm);
    }
    // Write expected total size so resume can detect upstream file changes
    if let ContentLength::Exact(total) = total_content_length {
        xattr_helpers::write_expected_size(&outfile, &outpath, total.get());
    }

    if resume_offset > 0 {
        info!(
            "Resuming and serving file {} from mirror {} for client {} at {}...",
            conn_details.debname,
            conn_details.mirror,
            conn_details.client,
            HumanFmt::Size(resume_offset)
        );
    } else {
        info!(
            "Downloading and serving new file {} from mirror {} for client {}...",
            conn_details.debname, conn_details.mirror, conn_details.client
        );
    }

    let upstream_metadata = Arc::new(UpstreamMetadata::from_upstream(
        upstream_etag,
        upstream_last_modified,
    ));

    let dbarrier = ibarrier
        .download(
            outpath.to_path_buf(),
            total_content_length,
            reservation,
            Arc::clone(&upstream_metadata),
        )
        .await;

    {
        let cd = conn_details.clone();
        let raw_uri_path = req.uri().path().to_owned();
        tokio::task::spawn(async move {
            download_file(
                &cd,
                warn_on_override,
                (body, body_content_length),
                (outfile, outpath),
                dbarrier,
                resume_offset,
                upstream_request_sent,
                raw_uri_path,
            )
            .await;
        });
    }

    if conn_details.cached_flavor != CachedFlavor::Volatile
        && config.experimental_parallel_hack_enabled
    {
        let curr_downloads = appstate.active_downloads.download_count();

        if config
            .experimental_parallel_hack_maxparallel
            .is_none_or(|max_parallel| curr_downloads <= max_parallel.get())
            && config
                .experimental_parallel_hack_minsize
                .is_none_or(|size| total_content_length.upper() > size)
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

                let mut response_builder = Response::builder()
                    .status(config.experimental_parallel_hack_statuscode)
                    .header(DATE, &*format_http_date())
                    .header(VIA, APP_VIA)
                    .header(CONNECTION, "keep-alive");

                if config.experimental_parallel_hack_retryafter != 0 {
                    response_builder = response_builder.header(
                        RETRY_AFTER,
                        HeaderValue::from(config.experimental_parallel_hack_retryafter),
                    );
                }

                let response = response_builder
                    .body(empty_body())
                    .expect("Response is valid");

                trace!("Outgoing parallel download hack response: {response:?}");

                return response;
            }
        }
    }

    serve_downloading_file(conn_details, req, status, Some(&upstream_metadata)).await
}

/// Create a TCP connection to host:port, build a tunnel between the connection and
/// the upgraded connection.
async fn tunnel(
    client: ClientInfo,
    upgraded: hyper::upgrade::Upgraded,
    host: &str,
    port: NonZero<u16>,
) -> std::io::Result<()> {
    let start = PreciseInstant::now();
    let config = global_config();

    /* Connect to remote server */
    let mut server = match tokio::time::timeout(
        config.http_timeout,
        tokio::net::TcpStream::connect((host, port.get())),
    )
    .await
    {
        Ok(result) => result?,
        Err(_timeout @ tokio::time::error::Elapsed { .. }) => {
            metrics::HTTP_TIMEOUT_UPSTREAM_CONNECT.increment();
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!(
                    "tunnel connect timed out after {}",
                    HumanFmt::Time(config.http_timeout)
                ),
            ));
        }
    };
    // Disable Nagle on the tunnel: TLS handshake records and HTTP request
    // headers are interactive, and a tunnel cannot coalesce them on our behalf.
    if config.upstream_tcp_nodelay
        && let Err(err) = server.set_nodelay(true)
    {
        warn_once_or_debug!(
            "Failed to set TCP_NODELAY on upstream tunnel to {host}:{port}:  {}",
            ErrorReport(&err)
        );
    }
    let mut upgraded = TokioIo::new(upgraded);

    /* Proxying data */
    let bufsize = config.buffer_size;

    // not rate-checked
    let (from_client, from_server) =
        tokio::io::copy_bidirectional_with_sizes(&mut upgraded, &mut server, bufsize, bufsize)
            .await?;

    metrics::BYTES_TUNNELED_CLIENT_TO_UPSTREAM.increment_by(from_client);
    metrics::BYTES_TUNNELED_UPSTREAM_TO_CLIENT.increment_by(from_server);

    info!(
        "Tunneled client {client} wrote {} and received {} from {host}:{port} in {}",
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
    let cache_path = conn_details.cache_file_path();

    match tokio::fs::File::options()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW)
        .open(&cache_path)
        .await
    {
        Ok(file) => {
            // CACHE_HITS only counts permanent-file hits; volatile hits live
            // in VOLATILE_HIT / VOLATILE_REFETCHED.
            #[cfg(not(feature = "sendfile"))]
            if conn_details.cached_flavor == CachedFlavor::Permanent {
                metrics::CACHE_HITS.increment();
            }

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
                    serve_volatile_file(conn_details, req, file, cache_path, appstate).await
                }
                CachedFlavor::Permanent => {
                    serve_cached_file(conn_details, &req, file, cache_path, None, None).await
                }
            }
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            #[cfg(not(feature = "sendfile"))]
            match conn_details.cached_flavor {
                CachedFlavor::Permanent => metrics::CACHE_MISSES.increment(),
                CachedFlavor::Volatile => {
                    // Cleanup-synthetic probes bypass sendfile's pre-bump on
                    // the volatile-not-found path; exclude them so the
                    // dashboard ratio reflects real client behavior only.
                    if !conn_details.client.is_cleanup_synthetic() {
                        metrics::VOLATILE_REFETCHED.increment();
                    }
                }
            }

            match appstate.active_downloads.insert(
                &conn_details.mirror,
                &conn_details.debname,
                conn_details.layout,
            ) {
                InsertOutcome::Originator { init_tx, status } => {
                    trace!(
                        "File {} not found, serving new version...",
                        cache_path.display()
                    );
                    serve_new_file(
                        conn_details,
                        status,
                        init_tx,
                        req,
                        CacheFileStat::New,
                        appstate,
                    )
                    .await
                }
                InsertOutcome::Joined { status } => {
                    trace!(
                        "File {} not found, serving in-download version...",
                        cache_path.display()
                    );
                    info!(
                        "Serving file {} already in download from mirror {} for client {}...",
                        conn_details.debname, conn_details.mirror, conn_details.client
                    );
                    serve_downloading_file(conn_details, req, status, None).await
                }
            }
        }
        Err(err) => {
            metrics::CACHE_IO_FAILURE.increment();
            error!(
                "Failed to open file `{}`:  {}",
                cache_path.display(),
                ErrorReport(&err)
            );
            quick_response(StatusCode::INTERNAL_SERVER_ERROR, "Cache Access Failure")
        }
    }
}

#[must_use]
fn connect_response(client: ClientInfo, req: Request<Incoming>) -> Response<ProxyCacheBody> {
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
            metrics::AUTHZ_REJECTED_CLIENT.increment();
            return quick_response(StatusCode::FORBIDDEN, "Unauthorized client");
        }
    }

    if !config.https_tunnel_enabled {
        info!("Rejecting https tunnel request for client {client}");
        metrics::TUNNEL_REJECTED_POLICY.increment();
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

    // Bound the authority length before any further work. hyper already
    // bounds the request line, but defending here keeps the CONNECT path
    // self-contained against any future relaxation of those limits.
    if let Some(auth) = req.uri().authority()
        && auth.as_str().len() > limits::MAX_AUTHORITY_LEN
    {
        warn_once_or_info!(
            "Oversized CONNECT authority from client {client}: {} bytes",
            auth.as_str().len()
        );
        return quick_response(StatusCode::BAD_REQUEST, "Invalid CONNECT address");
    }

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
        info!("Rejecting https tunnel request for client {client} to disallowed port {port}");
        metrics::TUNNEL_REJECTED_POLICY.increment();
        return quick_response(StatusCode::FORBIDDEN, "HTTPS tunnel port not permitted");
    }

    if !config.https_tunnel_allowed_mirrors.is_empty()
        && config
            .https_tunnel_allowed_mirrors
            .binary_search_by(|d| str::cmp(d, host.as_str()))
            .is_err()
    {
        info!("Rejecting https tunnel request for client {client} due to disallowed host {host}");
        metrics::AUTHZ_REJECTED_TUNNEL_MIRROR.increment();
        return quick_response(StatusCode::FORBIDDEN, "HTTPS tunnel target not permitted");
    }

    let tunnel_guard = if let Some(max) = config.https_tunnel_max_connections_per_client {
        let Some(guard) = tunnel_limiter::try_acquire(client.ip(), max) else {
            info!(
                "Rejecting https tunnel request for client {client}: \
                     concurrent connection limit ({max}) reached"
            );
            metrics::TUNNEL_REJECTED_CAPACITY.increment();
            return quick_response(
                StatusCode::TOO_MANY_REQUESTS,
                "Too many concurrent HTTPS tunnel connections",
            );
        };
        Some(guard)
    } else {
        None
    };

    // Account for the active tunnel regardless of whether the per-IP cap
    // is configured, so `CONNECT_TUNNEL_ACTIVE_PEAK` and the dashboard's
    // active count stay accurate on unlimited deployments.
    let active_tunnel_guard = tunnel_limiter::ActiveTunnelGuard::new();

    metrics::TUNNEL_CONNECTS_TOTAL.increment();
    info!("Using uncached tunnel for client {client} to {host}:{port}");

    tokio::task::spawn(async move {
        let _tunnel_guard = tunnel_guard;
        let _active_tunnel_guard = active_tunnel_guard;
        match hyper::upgrade::on(req).await {
            Ok(upgraded) => {
                if let Err(err) = tunnel(client, upgraded, &host, port).await {
                    metrics::TUNNEL_TRANSFER_FAILED.increment();
                    // OS-level `ETIMEDOUT` (TCP keepalive / `TCP_USER_TIMEOUT`)
                    // is a network condition, not a code error; log at info.
                    if err.kind() == std::io::ErrorKind::TimedOut {
                        info!(
                            "Tunnel for client {client} to {host}:{port} timed out:  {}",
                            ErrorReport(&err)
                        );
                    } else if is_peer_disconnect(&err) {
                        info!(
                            "Tunnel for client {client} to {host}:{port} closed by peer:  {}",
                            ErrorReport(&err)
                        );
                    } else {
                        error!(
                            "Error tunneling connection for client {client} to {host}:{port}:  {}",
                            ErrorReport(&err)
                        );
                    }
                }
            }
            Err(err) => {
                metrics::TUNNEL_TRANSFER_FAILED.increment();
                error!(
                    "Error upgrading connection for client {client} to {host}:{port}:  {}",
                    ErrorReport(&err)
                );
            }
        }
    });

    let response = Response::builder()
        .header(SERVER, APP_NAME)
        .header(VIA, APP_VIA)
        .header(DATE, &*format_http_date())
        .body(empty_body())
        .expect("HTTP response is valid");

    trace!("Outgoing response: {response:?}");

    response
}

#[inline]
async fn pre_process_client_request_wrapper(
    client: ClientInfo,
    req: Request<Incoming>,
    appstate: AppState,
) -> Result<Response<ProxyCacheBody>, Infallible> {
    let response = pre_process_client_request(client, req, appstate).await;
    metrics::record_client_status(response.status());
    Ok(response)
}

#[must_use]
async fn pre_process_client_request(
    client: ClientInfo,
    req: Request<Incoming>,
    appstate: AppState,
) -> Response<ProxyCacheBody> {
    trace!("Incoming request: {req:?}");

    metrics::REQUESTS_TOTAL.increment();

    let config = global_config();

    match req.method() {
        &Method::CONNECT => return connect_response(client, req),
        &Method::GET => {}
        m => {
            warn_once_or_info!("Unsupported request method {m} from client {client}");
            return quick_response(StatusCode::METHOD_NOT_ALLOWED, "Method not supported");
        }
    }

    // Proxy GET requests always use http://, HTTPS goes through CONNECT.
    // Reject any other scheme (e.g. ftp://, file://).
    if let Some(scheme) = req.uri().scheme()
        && *scheme != http::uri::Scheme::HTTP
    {
        warn_once_or_info!("Unsupported URI scheme `{scheme}` from client {client}");
        return quick_response(StatusCode::BAD_REQUEST, "Unsupported URI scheme");
    }

    let requested_host = if let Some(h) = req.uri().authority().map(Authority::host) {
        h.to_owned()
    } else {
        // RFC 7230 §5.4: A server MUST respond with a 400 status code to any
        // HTTP/1.1 request that lacks a Host header field.
        // HTTP/1.0 did not require Host, so only enforce for 1.1+.
        if req.version() == http::Version::HTTP_11 && !req.headers().contains_key(HOST) {
            return quick_response(StatusCode::BAD_REQUEST, "Missing Host header");
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
                metrics::AUTHZ_REJECTED_WEBUI.increment();
                return quick_response(StatusCode::FORBIDDEN, "Unauthorized client");
            }
        }

        return serve_web_interface(req.uri(), &appstate)
            .await
            .into_hyper_response();
    };

    let requested_port = match req.uri().port_u16() {
        Some(port) => {
            let Some(port) = NonZero::new(port) else {
                warn_once_or_info!("Unsupported request port 0 from client {client}");
                return quick_response(StatusCode::BAD_REQUEST, "Invalid port");
            };
            Some(port)
        }
        None => None,
    };

    let requested_host = match authorize_cache_access(&client, &requested_host) {
        Ok(rh) => rh,
        Err((status, msg)) => return quick_response(status, msg),
    };

    if req.body().size_hint().exact() != Some(0) {
        // Also fires for unknown-length bodies, whose lower bound can be 0.
        warn_once_or_info!(
            "Request from client {client} has a body (at least {} bytes), not forwarding it: {} {}",
            req.body().size_hint().lower(),
            req.method(),
            req.uri()
        );
    }
    let (parts, _body) = req.into_parts();
    let req = Request::from_parts(parts, Empty::new());

    let (requested_host, passthrough_request_received_at) =
        match dispatch_request(req.uri().path(), requested_host, requested_port, &client).await {
            DispatchOutcome::Cache(plan) => {
                let conn_details = ConnectionDetails {
                    client,
                    request_received_at: plan.request_received_at,
                    mirror: plan.mirror,
                    aliased_host: plan.aliased_host,
                    debname: plan.debname,
                    cached_flavor: plan.cached_flavor,
                    layout: plan.layout,
                    resource_kind: plan.resource_kind,
                };
                return process_cache_request(conn_details, req, appstate).await;
            }
            DispatchOutcome::Reject(reason) => {
                let (status, msg) = reason.response_parts();
                return quick_response(status, msg);
            }
            DispatchOutcome::Passthrough {
                reason: _,
                requested_host,
                request_received_at,
            } => (requested_host, request_received_at),
        };

    assert_eq!(req.method(), Method::GET, "Filtered at function start");

    //
    // Simple proxy (without any caching)
    //

    warn_once_or_info!(
        "Proxying (without caching) request {} for client {client}",
        req.uri()
    );

    record_uncacheable(&requested_host, req.uri().path());

    let (mut parts, _body) = req.into_parts();
    parts
        .headers
        .insert(USER_AGENT, HeaderValue::from_static(APP_USER_AGENT));

    // TODO: tweak http version?
    let fwd_request = Request::from_parts(parts, Empty::new());

    trace!("Forwarded request: {fwd_request:?}");

    let fwd_request_sent = PreciseInstant::now();
    // The returned parts serve the origin extraction and the rare
    // redirect-follow below — no up-front HeaderMap clone per request.
    let (fwd_response, mut parts) =
        match request_with_retry(&appstate.https_client, fwd_request).await {
            Ok(rp) => rp,
            Err(err) => return upstream_error_response(&err),
        };
    let request_path = parts.uri.path().to_owned();

    trace!("Forwarded response: {fwd_response:?}");

    if (fwd_response.status().is_success() || fwd_response.status().is_redirection())
        && let Some(origin) =
            Origin::from_path(parts.uri.path(), requested_host.clone(), requested_port)
    {
        debug!("Extracted origin: {origin:?}");

        // TODO: cache some of them?
        if !cache_layout::is_pseudo_arch(&origin.architecture) {
            let cmd = DatabaseCommand::Origin(DbCmdOrigin { origin });
            send_db_command(cmd).await;
        }
    }

    if matches!(
        fwd_response.status(),
        StatusCode::MOVED_PERMANENTLY
            | StatusCode::FOUND
            | StatusCode::TEMPORARY_REDIRECT
            | StatusCode::PERMANENT_REDIRECT
    ) && let Some(moved_uri) = fwd_response
        .headers()
        .get(LOCATION)
        .and_then(|lc| lc.to_str().ok())
        .and_then(|lc_str| lc_str.parse::<hyper::Uri>().ok())
    {
        debug!("Requested URI: {}, Moved URI: {moved_uri}", parts.uri);

        if moved_uri.scheme().is_some_and(|scheme| {
            *scheme == http::uri::Scheme::HTTP || *scheme == http::uri::Scheme::HTTPS
        }) && let Some(moved_auth) = moved_uri.authority()
            && is_host_allowed_cached(moved_auth.host())
        {
            // Update the Host header so it matches the redirect target,
            // otherwise the header from the original request would be
            // sent to a different mirror.
            let redirected_host = host_header_from_uri(moved_auth);
            parts.headers.insert(HOST, redirected_host);
            parts.uri = moved_uri;
            let redirected_request = Request::from_parts(parts, Empty::new());

            trace!("Redirected request: {redirected_request:?}");

            let redirected_request_sent = PreciseInstant::now();
            let redirected_response =
                match request_with_retry(&appstate.https_client, redirected_request).await {
                    Ok((r, _parts)) => r,
                    Err(err) => return upstream_error_response(&err),
                };

            trace!("Redirected response: {redirected_response:?}");

            let (parts, body) = redirected_response.into_parts();

            metrics::REQUESTS_PASSTHROUGH.increment();
            let counted = ClientCountedBody::new(PassthroughBody::new(
                body,
                passthrough_request_received_at,
                redirected_request_sent,
                requested_host.to_string(),
                request_path.clone(),
                client,
            ));

            let rated = MaybeRated::new(
                counted,
                config.min_download_rate,
                config.rate_check_timeframe,
                RateCheckDirection::Client,
            );

            let body = ProxyCacheBody::Boxed(BoxBody::new(rated.map_err(move |err| match *err {
                RateCheckedBodyErr::RateTimeout(error) => {
                    Box::new(ProxyCacheError::ClientDownloadRate { error, client })
                }
                RateCheckedBodyErr::Inner(ierr) => ierr.into(),
            })));

            let mut response = Response::from_parts(parts, body);
            response
                .headers_mut()
                .append(VIA, HeaderValue::from_static(APP_VIA));

            trace!("Outgoing response: {response:?}");

            return response;
        }
    }

    let (parts, body) = fwd_response.into_parts();

    metrics::REQUESTS_PASSTHROUGH.increment();
    let counted = ClientCountedBody::new(PassthroughBody::new(
        body,
        passthrough_request_received_at,
        fwd_request_sent,
        requested_host.to_string(),
        request_path,
        client,
    ));

    let rated = MaybeRated::new(
        counted,
        config.min_download_rate,
        config.rate_check_timeframe,
        RateCheckDirection::Client,
    );

    let body = ProxyCacheBody::Boxed(BoxBody::new(rated.map_err(move |err| match *err {
        RateCheckedBodyErr::RateTimeout(error) => {
            Box::new(ProxyCacheError::ClientDownloadRate { error, client })
        }
        RateCheckedBodyErr::Inner(ierr) => ierr.into(),
    })));

    let mut response = Response::from_parts(parts, body);

    response
        .headers_mut()
        .append(VIA, HeaderValue::from_static(APP_VIA));

    trace!("Outgoing response: {response:?}");

    response
}

/// Build a `Host` header value matching the given authority.
///
/// IPv6 hosts are kept bracketed per RFC 3986 §3.2.2, and any explicit
/// port is appended.
fn host_header_from_uri(auth: &Authority) -> HeaderValue {
    let host = auth.host();
    let value = match auth.port_u16() {
        Some(port) => format!("{host}:{port}"),
        None => host.to_owned(),
    };
    HeaderValue::try_from(value).expect("host value is valid")
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
    fn hyper_is_peer_disconnect(err: &hyper::Error) -> bool {
        if let Some(err) = std::error::Error::source(&err)
            && let Some(ioerr) = err.downcast_ref::<std::io::Error>()
            && is_peer_disconnect(ioerr)
        {
            return true;
        }

        false
    }

    #[must_use]
    fn is_rate_timeout(err: &hyper::Error) -> Option<&ProxyCacheError> {
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
        .timer(hyper_util::rt::TokioTimer::new())
        .header_read_timeout(global_config().client_idle_timeout)
        .serve_connection(
            TokioIo::new(stream),
            service_fn(move |req| {
                pre_process_client_request_wrapper(client, req, appstate.clone())
            }),
        )
        .with_upgrades()
        .await
    {
        if err.is_incomplete_message() || hyper_is_peer_disconnect(&err) {
            // Hyper does not expose per-frame write errors, so we cannot
            // tell whether the disconnect happened mid-body, between
            // pipelined requests, or before any response was started. Bump
            // on the full outer guard — both peer-disconnect and incomplete-
            // message framing breaks indicate the client went away — since
            // the alternative (silently dropping these) gives the operator
            // a worse signal. See the docstring on
            // CLIENT_DISCONNECTED_MID_BODY for the scope caveat.
            metrics::CLIENT_DISCONNECTED_MID_BODY.increment();
            info!(
                "Connection to client {client} disconnected:  {}",
                ErrorReport(&err)
            );
        } else if err.is_timeout() {
            // hyper's `header_read_timeout` (driven by `client_idle_timeout`)
            // fires on idle keep-alive and slowloris-shaped clients. This is
            // benign disconnect behaviour, not a server fault — log at debug
            // and leave HTTP_TIMEOUT_CLIENT_HEADER untouched (the sendfile
            // backend is the sole owner of that counter).
            debug!("Client {client} idle-timed out before sending request headers");
        } else if let Some(perr) = is_rate_timeout(&err) {
            info!("{perr}");
        } else {
            error!(
                "Error serving connection for client {client}:  {}",
                ErrorReport(&err)
            );
        }
    }
}

pub(crate) mod tunnel_limiter {
    use std::net::IpAddr;
    use std::num::NonZero;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use hashbrown::HashMap;

    use crate::metrics;

    static TUNNEL_CONNECTIONS: std::sync::LazyLock<parking_lot::Mutex<HashMap<IpAddr, usize>>> =
        std::sync::LazyLock::new(|| parking_lot::Mutex::new(HashMap::new()));

    /// Total active tunnels across all source IPs. Updated by
    /// [`ActiveTunnelGuard`] on every CONNECT regardless of whether the
    /// per-IP cap is configured, so the dashboard reflects real activity.
    static ACTIVE_TUNNELS: AtomicUsize = AtomicUsize::new(0);

    /// Current number of active HTTPS tunnel connections across all clients.
    #[must_use]
    pub(crate) fn active_tunnels() -> usize {
        ACTIVE_TUNNELS.load(Ordering::Relaxed)
    }

    /// Unconditionally count an active CONNECT tunnel for the lifetime of
    /// this guard. Updates [`metrics::CONNECT_TUNNEL_ACTIVE_PEAK`] on
    /// construction.
    ///
    /// Independent from the per-IP rate-limit [`TunnelGuard`] so the
    /// dashboard's "active" and "peak" counts are maintained even when
    /// `https_tunnel_max_connections_per_client` is unset.
    pub(super) struct ActiveTunnelGuard {
        _private: (),
    }

    impl ActiveTunnelGuard {
        pub(super) fn new() -> Self {
            let current = ACTIVE_TUNNELS.fetch_add(1, Ordering::Relaxed) + 1;
            metrics::CONNECT_TUNNEL_ACTIVE_PEAK.update(current as u64);
            Self { _private: () }
        }
    }

    impl Drop for ActiveTunnelGuard {
        fn drop(&mut self) {
            ACTIVE_TUNNELS.fetch_sub(1, Ordering::Relaxed);
        }
    }

    /// Try to acquire a per-source-IP tunnel slot.
    /// Returns `Some(TunnelGuard)` if under the limit, `None` if at capacity.
    /// Does *not* update the active-tunnel counter — that's
    /// [`ActiveTunnelGuard`]'s job, and the caller composes both guards.
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

#[cfg(test)]
mod tests {
    use super::{Uri, host_header_from_uri};

    #[test]
    fn host_header_from_uri_plain_host() {
        let uri: Uri = "http://deb.debian.org/foo".parse().unwrap();
        assert_eq!(
            host_header_from_uri(uri.authority().unwrap()),
            "deb.debian.org"
        );
    }

    #[test]
    fn host_header_from_uri_with_port() {
        let uri: Uri = "http://mirror.example.com:8080/foo".parse().unwrap();
        assert_eq!(
            host_header_from_uri(uri.authority().unwrap()),
            "mirror.example.com:8080"
        );
    }

    #[test]
    fn host_header_from_uri_ipv6_bracketed() {
        let uri: Uri = "http://[2001:db8::1]/foo".parse().unwrap();
        assert_eq!(
            host_header_from_uri(uri.authority().unwrap()),
            "[2001:db8::1]"
        );
    }

    #[test]
    fn host_header_from_uri_ipv6_with_port() {
        let uri: Uri = "http://[2001:db8::1]:8080/foo".parse().unwrap();
        assert_eq!(
            host_header_from_uri(uri.authority().unwrap()),
            "[2001:db8::1]:8080"
        );
    }
}
