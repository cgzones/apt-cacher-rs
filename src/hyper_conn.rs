use std::{
    convert::Infallible, error::Error as _, num::NonZero, os::unix::fs::MetadataExt as _,
    path::Path, path::PathBuf, sync::Arc,
};

use futures_util::TryStreamExt as _;
use http::{
    HeaderName, HeaderValue, Method, Request, Response, StatusCode, Uri,
    header::{
        ACCEPT, ACCEPT_RANGES, AGE, CACHE_CONTROL, CONNECTION, CONTENT_LENGTH, CONTENT_RANGE,
        CONTENT_TYPE, DATE, ETAG, HOST, IF_MODIFIED_SINCE, IF_NONE_MATCH, IF_RANGE, LAST_MODIFIED,
        LOCATION, RANGE, RETRY_AFTER, SERVER, USER_AGENT, VIA,
    },
    uri::Authority,
};
use http_body::{Body, Frame};
use http_body_util::{BodyExt as _, Empty, StreamBody, combinators::BoxBody};
use hyper::{body::Incoming, server::conn::http1, service::service_fn};
use hyper_util::{client::legacy::connect::HttpConnector, rt::tokio::TokioIo};
#[cfg(feature = "mmap")]
use memmap2::{Advice, MmapOptions};
use rand::distr::{Bernoulli, Distribution as _};
use tokio::io::{AsyncReadExt as _, AsyncSeekExt as _, AsyncWriteExt as _};
use tracing::{debug, error, info, trace, warn};

#[cfg(feature = "mmap")]
use crate::mmap_body::MmapBody;
use crate::{
    APP_NAME, APP_USER_AGENT, APP_VIA, AppState, ClientInfo, ContentLength, Never, ProxyCacheBody,
    Scheme, VOLATILE_CACHE_MAX_AGE,
    accounted_body::{AccountedBody, Subject},
    active_downloads::{
        AbortReason, ActiveDownloadStatus, InsertOutcome, Serveable, await_serveable,
    },
    cache_conditional::{CacheInfo, RangeRequestHeaders, ServeParams, ServePlan},
    cache_layout::{self, CachedFlavor, ConnectionDetails, SUBDIR_TMP},
    cache_metadata::{self, UpstreamMetadata},
    cache_quota::QuotaExceeded,
    channel_body::ChannelBody,
    client_counter,
    connect_tunnel::{ConnectReject, validate_connect_target},
    content_type_for_cached_file,
    database_task::{DatabaseCommand, DbCmdOrigin, DbCmdTransfer, TransferKind, send_db_command},
    deb_mirror::Origin,
    delivery::{Mechanism, Role, ServeOutcome, finish_cached_serve},
    error::{ErrorReport, MirrorDownloadRate, ProxyCacheError, UpstreamFetchError},
    full_body, global_cache_quota, global_config, global_verify_throttle,
    guards::{DownloadBarrier, InitBarrier},
    http_etag::{is_valid_etag, write_etag},
    http_last_modified::write_last_modified,
    http_range::{HttpDate, format_http_date},
    humanfmt::HumanFmt,
    metrics,
    permitted_host_cache::{authorize_cache_access, is_host_allowed_cached},
    precise_instant::PreciseInstant,
    quick_response,
    rate_checked_body::{MaybeRated, RateCheckedBodyErr},
    rate_checker::RateCheckDirection,
    rate_log,
    request_dispatch::{
        ClientAcls, DispatchOutcome, RequestKind, RequestTarget, dispatch_request,
        preflight_method, preflight_target,
    },
    scheme_cache, static_assert, tunnel_limiter,
    uncacheables::record_uncacheable,
    upstream_head::{
        DownloadPlan, RejectReason, ResumeAnomaly, ResumeState, UpstreamHead, plan_download,
        plan_fresh_download,
    },
    upstream_retry,
    utils::{
        self, CacheAccessFailure, TempPath, hint_sequential_read, is_peer_disconnect,
        regular_file_metadata, tokio_nofollow_options, tokio_tempfile, touch_volatile_mtime,
    },
    warn_on_content_type_mismatch, warn_once_or_debug, warn_once_or_info,
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
/// the whole `HeaderMap` up front.
pub(crate) async fn request_with_retry(
    client: &HttpClient,
    request: Request<Empty<bytes::Bytes>>,
) -> Result<(Response<Incoming>, http::request::Parts), hyper_util::client::legacy::Error> {
    // Auto-mode's HTTPS-upgrade revert branch only fires once `attempt`
    // has crossed this threshold; below it, transient connect errors
    // retry without reverting the scheme.
    const HTTPS_UPGRADE_REVERT_AFTER_ATTEMPTS: u32 = 2;
    // The Always-mode terminal-failure HTTPS_UPGRADE_FAILED bump below
    // (gated on an exhausted retry budget with `https_upgrade_test` still
    // set) relies on the Auto-mode revert firing first. If MAX_ATTEMPTS
    // were ever <= HTTPS_UPGRADE_REVERT_AFTER_ATTEMPTS, Auto mode would
    // also fall through here with the flag set and bump HTTPS_UPGRADE_FAILED
    // instead of HTTPS_UPGRADE_REVERTED. (A wall-clock `upstream_retry_budget`
    // spent before the third attempt has the same effect; the
    // ATTEMPTED == SUCCEEDED + REVERTED + FAILED identity holds either way.)
    static_assert!(upstream_retry::MAX_ATTEMPTS > HTTPS_UPGRADE_REVERT_AFTER_ATTEMPTS);

    debug_assert_eq!(
        request.body().size_hint().exact(),
        Some(0),
        "Invariant of Empty"
    );

    let (mut parts, _body) = request.into_parts();

    let orig_scheme = parts.uri.scheme().cloned();

    let mut https_upgrade_test = false;
    let mut revertible = false;

    if let Some(os) = &orig_scheme
        && *os != http::uri::Scheme::HTTP
    {
        // A non-HTTP original scheme (e.g. an explicit https:// proxied URL) is
        // left untouched; the scheme cache is hyper-specifically not consulted.
        debug!("Not altering {os} scheme for request {}", parts.uri);
    } else if let Some(auth) = parts.uri.authority() {
        let decision = scheme_cache::resolve(auth.into(), global_config());
        let scheme = if decision.is_upgrade_attempt() {
            debug!(
                "No cached scheme for host {auth}, trying https upgrade from original scheme {orig_scheme:?}..."
            );
            https_upgrade_test = true;
            revertible = decision.revertible();
            metrics::HTTPS_UPGRADE_ATTEMPTED.increment();
            http::uri::Scheme::HTTPS
        } else {
            let scheme = decision
                .fixed_scheme()
                .expect("non-upgrade decision has a fixed scheme");
            debug!("Using {scheme} scheme for host {auth}, original scheme is {orig_scheme:?}");
            scheme.into()
        };
        // `auth` is last used above; NLL ends its borrow so `parts.uri` can be consumed.
        let mut uri_parts = parts.uri.into_parts();
        uri_parts.scheme = Some(scheme);
        parts.uri = Uri::from_parts(uri_parts).expect("valid parts");
    }

    #[expect(
        clippy::items_after_statements,
        reason = "keep definition before grouped call sites"
    )]
    async fn inner_loop(
        client: &HttpClient,
        mut parts: http::request::Parts,
        orig_scheme: Option<http::uri::Scheme>,
        revertible: bool,
        mut https_upgrade_test: bool,
    ) -> Result<
        (Response<Incoming>, http::request::Parts),
        Box<(hyper_util::client::legacy::Error, Uri)>,
    > {
        let mut backoff = upstream_retry::Backoff::new(
            global_config().upstream_retry_budget,
            coarsetime::Instant::now(),
        );

        loop {
            let req_clone = Request::from_parts(parts.clone(), Empty::new());

            let _: Never = match client.request(req_clone).await {
                Ok(response) => {
                    if https_upgrade_test {
                        metrics::HTTPS_UPGRADE_SUCCEEDED.increment();
                    }
                    if let Some(auth) = parts.uri.authority() {
                        if let Some(scheme) = parts.uri.scheme().and_then(Scheme::from_uri_scheme) {
                            if scheme_cache::record_success(auth.into(), scheme) {
                                debug!(
                                    "Added cached {scheme} scheme for host {auth}, original scheme was {orig_scheme:?}"
                                );
                            }
                        } else {
                            debug!(
                                "Not caching unsupported scheme {:?} for host {auth}",
                                parts.uri.scheme()
                            );
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
                        "Upstream request to {} failed; returning 502:  {}",
                        parts.uri,
                        ErrorReport(&err)
                    );
                    return Err(Box::new((err, parts.uri)));
                }
                Err(err) => {
                    if is_io_timed_out_in_chain(&err) {
                        metrics::HTTP_TIMEOUT_UPSTREAM_CONNECT.increment();
                    }
                    let attempt = backoff.attempt();
                    if attempt > HTTPS_UPGRADE_REVERT_AFTER_ATTEMPTS
                        && https_upgrade_test
                        && revertible
                    {
                        // `revertible` is set only for an uncached Auto-mode upgrade
                        // (see scheme_cache::decide): no cached scheme exists to
                        // preserve and the mode is necessarily Auto.

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
                        backoff.reset_delay();
                        // The revert iteration is another upstream attempt
                        // even though the retry budget is not consumed for it.
                        // Match `Backoff::next_retry` in counting it as a retry.
                        metrics::UPSTREAM_RETRIES.increment();
                        continue;
                    }

                    let Some(delay) = backoff.next_retry(coarsetime::Instant::now()) else {
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
                        if let Some(auth) = parts.uri.authority()
                            && let Some(scheme) = scheme_cache::record_failure(auth.into())
                        {
                            // A learned scheme is sticky, so losing it silently
                            // changes how every later request to this host is
                            // dialled (an evicted https entry can hand the host
                            // back to plain http under Auto mode).
                            warn_once_or_info!(
                                "Evicted cached {scheme} scheme for host {auth} after {attempt} connection attempts, original scheme was {orig_scheme:?}; the next request re-decides the scheme"
                            );
                        }

                        // Single WARN authority for upstream-fetch failures: the
                        // non-connect arm above already warns; mirror it here so a
                        // connect-exhaustion terminal is logged once too (callers no
                        // longer re-warn). The limit names which budget stopped the
                        // retries -- attempt cap or `upstream_retry_budget`.
                        warn_once_or_info!(
                            "Upstream request to {} failed after {attempt} connection attempts ({}); returning 502:  {}",
                            parts.uri,
                            backoff.limit(),
                            ErrorReport(&err)
                        );

                        return Err(Box::new((err, parts.uri)));
                    };

                    debug!(
                        "Failed to connect to {} after {attempt} connection attempts, will retry in {} ms:  {}",
                        parts.uri,
                        delay.as_millis(),
                        ErrorReport(&err)
                    );

                    tokio::time::sleep(delay).await;

                    continue;
                }
            };
        }
    }

    if https_upgrade_test {
        let client = client.clone();

        // Spawn a new task such that even if the client disconnects,
        // the task will continue to run and initialize the scheme cache.
        tokio::task::spawn(async move {
            let result = inner_loop(&client, parts, orig_scheme, revertible, true).await;
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
        inner_loop(client, parts, orig_scheme, false, false)
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

/// Wrap a client-facing body in the configured client-rate check and box it
/// into [`ProxyCacheBody`], mapping a rate timeout to
/// `ProxyCacheError::ClientDownloadRate` for `client`.
fn rated_client_body<B>(body: B, client: ClientInfo) -> ProxyCacheBody
where
    B: Body<Data = bytes::Bytes> + Send + Sync + 'static,
    B::Error: Into<Box<ProxyCacheError>>,
{
    let config = global_config();
    let rated = MaybeRated::new(
        body,
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
    ProxyCacheBody::Boxed(BoxBody::new(rated))
}

#[cfg(feature = "mmap")]
#[inline(always)]
fn serve_cached_file_mmap(
    conn_details: ConnectionDetails,
    file: tokio::fs::File,
    file_path: &Path,
    aliased: &str,
    cache_info: &CacheInfo,
    params: ServeParams,
) -> Response<ProxyCacheBody> {
    let content_start = params.content_start;
    let content_length: usize = match params.content_length.try_into() {
        Ok(c) => c,
        Err(_err @ std::num::TryFromIntError { .. }) => {
            error!(
                "Content-Length of {} bytes for file `{}` from mirror {}{aliased} for client {} is too large; returning 500",
                params.content_length,
                file_path.display(),
                conn_details.mirror,
                conn_details.client
            );
            return quick_response(StatusCode::INTERNAL_SERVER_ERROR, "Cache Access Failure");
        }
    };

    debug!(
        "Serving cached file {} from mirror {}{aliased} for client {} via mmap...",
        conn_details.debname, conn_details.mirror, conn_details.client
    );

    // mmap path uses madvise(SEQUENTIAL) on the mapping itself, so no
    // posix_fadvise is needed here.

    trace!(
        "Using mmap(2) with start={content_start} and length={content_length} from content_range={:?} for file `{}`",
        params.content_range,
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
                "Failed to mmap downloaded file `{}`; returning 500:  {}",
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
                "Failed to advise memory mapping of file `{}`; serving without the readahead hint:  {}",
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

    let memory_body = AccountedBody::new(
        MmapBody::new(memory_map, content_length),
        Subject::Cached {
            conn_details,
            mechanism: Mechanism::Mmap,
            size: content_length as u64,
            partial: params.is_partial(),
        },
        |never| match *never {},
    );

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
    serve_cached_file_response(cache_info, params, content_type, body)
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

    let md = match regular_file_metadata(&file, &file_path).await {
        Ok(data) => data,
        Err(CacheAccessFailure) => {
            return quick_response(StatusCode::INTERNAL_SERVER_ERROR, "Cache Access Failure");
        }
    };

    let CacheInfo {
        file_etag,
        last_modified_str,
        age,
        last_modified_for_ims: _,
    } = CacheInfo::with_meta(&md, upstream_metadata);

    let content_type = content_type_for_cached_file(&conn_details.debname);
    let (tx, rx) = tokio::sync::mpsc::channel(64);

    let client = conn_details.client;
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
                            "Failed to read from file `{}`; cancelling the stream:  {}",
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
                                if tx.send(Err(mdr)).await.is_err() {
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
                            "Invalid download state {:?} of file `{}`; cancelling the stream",
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
        let outcome = ServeOutcome {
            size: bytes,
            transferred: bytes,
            complete: !client_disconnected,
            partial: false,
            elapsed,
            abort: None,
        };
        if let Some(cmd) =
            finish_cached_serve(&conn_details, Mechanism::Channel, Role::LateJoiner, outcome)
        {
            send_db_command(DatabaseCommand::Transfer(cmd)).await;
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
    let body = rated_client_body(ChannelBody::new(rx, content_length), client);

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
        None => match regular_file_metadata(&file, &file_path).await {
            Ok(m) => m,
            Err(CacheAccessFailure) => {
                return quick_response(StatusCode::INTERNAL_SERVER_ERROR, "Cache Access Failure");
            }
        },
    };

    let file_size = mdata.len();

    let cache_key = conn_details.key();

    // Caller pre-resolves on the stale-volatile revalidation path;
    // otherwise fall back to the post-flight cache (lazy-loads xattr on miss).
    let resolved_meta = match prefetched_upstream_metadata {
        Some(meta) => UpstreamMetadataView::Borrowed(meta),
        None => UpstreamMetadataView::Arc(
            cache_metadata::store().resolve(&cache_key, &file, &file_path),
        ),
    };

    let cache_info = CacheInfo::with_meta(&mdata, &resolved_meta);
    let headers = RangeRequestHeaders::from_http(req.headers(), &conn_details.client);

    let params = match cache_info.plan(file_size, &headers, &conn_details.client) {
        ServePlan::Serve(params) => params,
        ServePlan::NotModified => {
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
                    HeaderValue::try_from(&*cache_info.last_modified_str)
                        .expect("HTTP date is valid"),
                )
                .header(AGE, HeaderValue::from(cache_info.age));

            if let Some(etag) = cache_info.file_etag.as_deref() {
                builder = builder.header(
                    ETAG,
                    HeaderValue::try_from(etag).expect("ETag is validated by read_etag"),
                );
            }

            let response = builder.body(empty_body()).expect("HTTP response is valid");

            trace!("Outgoing response: {response:?}");

            return response;
        }
        ServePlan::NotSatisfiable => {
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
    };

    #[cfg(feature = "mmap")]
    if params.content_length >= global_config().mmap_threshold.get() {
        // TODO: use become: https://github.com/rust-lang/rust/issues/112788
        return serve_cached_file_mmap(
            conn_details,
            file,
            &file_path,
            &aliased,
            &cache_info,
            params,
        );
    }

    // Buf path streams the file straight through; let the kernel grow its
    // readahead window accordingly.
    hint_sequential_read(&file, params.content_length, &file_path);

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
        &cache_info,
        params,
    )
    .await
}

#[expect(
    clippy::inline_always,
    reason = "function has only 1 caller and is a tail call"
)]
#[inline(always)]
async fn serve_cached_file_buf(
    conn_details: ConnectionDetails,
    mut file: tokio::fs::File,
    file_path: PathBuf,
    file_size: u64,
    cache_info: &CacheInfo,
    params: ServeParams,
) -> Response<ProxyCacheBody> {
    let start = params.content_start;
    let content_length = params.content_length;
    debug_assert!(
        start + content_length <= file_size,
        "range {start}+{content_length} must not exceed file size {file_size}"
    );

    let config = global_config();
    let client = conn_details.client;

    if let Err(err) = file.seek(std::io::SeekFrom::Start(start)).await {
        metrics::CACHE_IO_FAILURE.increment();
        error!(
            "Failed to seek cached file `{}` to offset {start}/{file_size}; returning 500:  {}",
            file_path.display(),
            ErrorReport(&err)
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

    let delivery_body = AccountedBody::new(
        StreamBody::new(reader_stream.map_ok(Frame::data)),
        Subject::Cached {
            conn_details,
            mechanism: Mechanism::Stream,
            size: content_length,
            partial: params.is_partial(),
        },
        is_peer_disconnect,
    );

    let body = rated_client_body(delivery_body, client);

    // TODO: use become: https://github.com/rust-lang/rust/issues/112788
    serve_cached_file_response(cache_info, params, content_type, body)
}

/// Shared response builder for `serve_cached_file_mmap` and
/// `serve_cached_file_buf`; always called as a tail call.
fn serve_cached_file_response(
    cache_info: &CacheInfo,
    params: ServeParams,
    content_type: &'static str,
    body: ProxyCacheBody,
) -> Response<ProxyCacheBody> {
    let ServeParams {
        http_status,
        content_start: _,
        content_length,
        content_range,
    } = params;
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
            HeaderValue::try_from(&*cache_info.last_modified_str).expect("date string is valid"),
        )
        .header(ACCEPT_RANGES, "bytes")
        .header(AGE, HeaderValue::from(cache_info.age));

    if let Some(ct) = content_range {
        response_builder = response_builder.header(
            CONTENT_RANGE,
            HeaderValue::try_from(ct).expect("content range string is valid"),
        );
    }

    if let Some(etag) = cache_info.file_etag.as_deref() {
        response_builder = response_builder.header(
            ETAG,
            HeaderValue::try_from(etag).expect("ETag is validated by read_etag"),
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
    match await_serveable(&status, &conn_details).await {
        Ok(Serveable::InProgress {
            file,
            path,
            content_length,
            rx,
            meta,
        }) => {
            serve_unfinished_file(conn_details, file, path, status, content_length, rx, &meta).await
        }
        Ok(Serveable::Complete { file, path, meta }) => {
            drop(status);
            // A caller-supplied snapshot (the stale-volatile revalidation
            // path) wins over what the status carried.
            let meta = match (prefetched_upstream_metadata, meta) {
                (Some(meta), _) => Some(UpstreamMetadataView::Borrowed(meta)),
                (None, meta) => meta.map(UpstreamMetadataView::Arc),
            };
            serve_cached_file(conn_details, &req, file, path, meta.as_deref(), None).await
        }
        Err(failure) => {
            drop(status);
            let (status_code, msg) = failure.response_parts();
            quick_response(status_code, msg)
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

    let mdata = match regular_file_metadata(&file, &file_path).await {
        Ok(data) => data,
        Err(CacheAccessFailure) => {
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
                "Volatile file `{}` age {} is within the {} freshness window, serving cached version...",
                file_path.display(),
                HumanFmt::Time(elapsed),
                HumanFmt::Time(VOLATILE_CACHE_MAX_AGE)
            );

            // Hyper owns hit/refetch accounting for every request it
            // processes: in sendfile builds requests only get here when
            // sendfile did NOT account them — either re-dispatched after a
            // `NotApplicable` handoff (sendfile's bumps are splice-only) or
            // arriving on an already-handed-off keep-alive connection that
            // bypasses sendfile entirely. Cleanup-synthetic probes
            // (task_cleanup's `.xz → .gz → raw` walk) would inflate the
            // user-facing counter — exclude them.
            if !conn_details.client.is_cleanup_synthetic() {
                metrics::VOLATILE_HIT.increment();
            }

            return serve_cached_file(conn_details, &req, file, file_path, None, Some(mdata)).await;
        }
    } else {
        warn_once_or_info!(
            "Volatile file `{}` was modified in the future; treating it as stale and refetching from upstream",
            file_path.display()
        );
    }

    // Hyper owns the parent refetch bump for every stale-volatile request it
    // processes (see the VOLATILE_HIT comment above: sendfile's bumps are
    // splice-only, and handed-off keep-alive connections bypass sendfile).
    // This dominates the VOLATILE_REFETCHED_* subset bumps in
    // `serve_new_file`. Cleanup-synthetic probes are operator bookkeeping,
    // not user traffic — exclude them so the dashboard ratio reflects real
    // client behavior only.
    if !conn_details.client.is_cleanup_synthetic() {
        metrics::VOLATILE_REFETCHED.increment();
    }

    match appstate.active_downloads.insert(conn_details.key()) {
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
        InsertOutcome::AtCapacity { max } => upstream_cap_rejection(&conn_details, max),
    }
}

async fn download_file(
    conn_details: &ConnectionDetails,
    warn_on_override: bool,
    input: (Incoming, ContentLength),
    output: (tokio::fs::File, TempPath),
    mut dbarrier: DownloadBarrier,
    resume_offset: u64,
    request_sent: PreciseInstant,
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
                            "Failed to extract frame from body for file {} from mirror {} (time={}, size={}, upstream_rate={}); aborting the download:  {}",
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
                        "Failed to flush partial data to `{}`; abandoning the download:  {}",
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
                    "More bytes received than expected for file {} from mirror {}: got {bytes} bytes, expected at most {}; aborting the download",
                    conn_details.debname,
                    conn_details.mirror,
                    content_length.upper()
                );
                return;
            }

            if let Err(err) = writer.write_all_buf(&mut chunk).await {
                metrics::CACHE_IO_FAILURE.increment();
                error!(
                    "Failed to write to file `{}`; aborting the download:  {}",
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
                    "Content-Length mismatch: expected {} bytes but got {} for file {} from mirror {}; leaving the download uncached",
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
                    "Content exceeded unknown-length limit: got {} bytes but limit is {} for file {} from mirror {}; leaving the download uncached",
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
            "Failed to flush file `{}`; leaving the download uncached:  {}",
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
            "Failed to create destination directory `{}`; leaving the download uncached:  {}",
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
                        "Target file `{}` already exists; overwriting (aliased={})",
                        dest_file_path.display(),
                        conn_details.aliased_host.is_some()
                    );
                }
                Ok(false) => {}
                Err(err) => {
                    warn!(
                        "Failed to check if `{}` exists; continuing with the rename:  {}",
                        dest_file_path.display(),
                        ErrorReport(&err)
                    );
                }
            }
        }

        if rbarrier
            .commit(outpath, dest_file_path, total_bytes)
            .await
            .is_err()
        {
            // commit() logged the failure and dropped the barrier (abort
            // path); its temp-file guard removed the partial. The client was
            // already served from the live stream.
            return;
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

    let cmd = DatabaseCommand::Transfer(DbCmdTransfer {
        mirror: conn_details.mirror.clone(),
        debname: conn_details.debname.clone(),
        size: total_bytes,
        elapsed,
        client_ip: conn_details.client.ip(),
        kind: TransferKind::Download,
    });
    send_db_command(cmd).await;
}

/// Log and build the canonical 503 for a download origination refused by the
/// `max_upstream_downloads` cap (`InsertOutcome::AtCapacity`). The
/// `UPSTREAM_DOWNLOAD_REJECTED_CAP` bump already happened inside
/// `ActiveDownloads::lookup_or_insert`, the enforcement site shared with the
/// splice backend.
#[must_use]
/// Parse a redirect response's `Location` into a URI.
///
/// The other reasons a redirect is not followed (relative target, unsupported
/// scheme, host not permitted) each log at the call site; a `Location` that
/// does not parse -- or is missing entirely -- would otherwise leave nothing but a
/// bare "failed with code 302" further down. `source` and `what` only name
/// the mirror and resource for the log line.
fn parse_redirect_location<B>(response: &Response<B>, source: &str, what: &str) -> Option<Uri> {
    let status = response.status();
    let Some(location) = response.headers().get(LOCATION) else {
        warn_once_or_debug!(
            "Upstream mirror {source} answered {status} for {what} without a Location header; forwarding the response to the client"
        );
        return None;
    };
    let parsed = location
        .to_str()
        .ok()
        .and_then(|lc_str| lc_str.parse::<Uri>().ok());
    if parsed.is_none() {
        warn_once_or_debug!(
            "Upstream mirror {source} sent an unparsable Location header {location:?} on {status} for {what}; forwarding the response to the client"
        );
    }
    parsed
}

fn upstream_cap_rejection(
    conn_details: &ConnectionDetails,
    max: NonZero<usize>,
) -> Response<ProxyCacheBody> {
    warn_once_or_info!(
        "Max upstream downloads ({max}) exceeded for {} from client {}; returning 503",
        conn_details.debname,
        conn_details.client
    );
    quick_response(
        StatusCode::SERVICE_UNAVAILABLE,
        "Too many concurrent upstream downloads",
    )
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
        &conn_details,
        req.uri().path(),
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
                    "Unhandled HTTP header `{name}` with value `{value:?}` in request from client {}; not forwarding it upstream",
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

    // Cleanup probes bypass the throttle: they run once per 24h cycle and a
    // 503 would hard-fail the index-fetch cascade; their commit outcome
    // still records/clears throttle state.
    if !conn_details.client.is_cleanup_synthetic()
        && let Some(throttled) = global_verify_throttle().check(conn_details.key())
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
            .header(DATE, &*format_http_date())
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
            let key = conn_details.key();

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
    let (resume_offset, resume_expected_total, resume_if_range, mut partial) = if conn_details
        .cached_flavor
        == CachedFlavor::Permanent
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
                return quick_response(StatusCode::INTERNAL_SERVER_ERROR, "Cache Access Failure");
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
    ) && let Some(moved_uri) = parse_redirect_location(
        &fwd_response,
        &conn_details.mirror.to_string(),
        &conn_details.debname,
    ) {
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
        } else if moved_uri.scheme().is_none() {
            // A relative Location (`/pool/...`) is legal per RFC 9110, but this
            // backend only follows absolute targets. Reported before the scheme
            // branch below, which would otherwise call it an unsupported scheme.
            debug!("Moved URI `{moved_uri}` is relative; not following the redirect");
        } else if moved_uri.scheme().is_none_or(|scheme| {
            *scheme != http::uri::Scheme::HTTP && *scheme != http::uri::Scheme::HTTPS
        }) {
            debug!("Scheme of moved URI `{moved_uri:?}` not supported");
        } else if let Some(moved_host) = moved_uri.host() {
            debug!("Host `{moved_host}` of moved URI not permitted");
        } else {
            debug!("Moved URI has no host; not following the redirect");
        }
    }

    // `cfstate` was only needed by reference for the conditional headers of
    // the requests above; a retry below is an unconditional fresh fetch.
    let cached = match cfstate {
        CacheFileStat::Volatile {
            file,
            file_path,
            local_modification_time: _,
            prev_size: _,
        } => Some((file, file_path)),
        CacheFileStat::New => None,
    };

    let mut head = UpstreamHead::from_response(&fwd_response);

    if let Some((_, file_path)) = &cached {
        // Only count "out of date" when upstream actually returned fresh
        // content (mirrors the splice path's non-200/non-206 passthrough in
        // `splice_proxy_drive`); a 4xx/5xx revalidation is not a fresh body.
        // Cleanup-synthetic probes bypass the parent counter (they bypass
        // sendfile and never bump VOLATILE_REFETCHED in the default build),
        // so counting them here would let the subset run ahead of the parent;
        // the UPTODATE site below excludes them for the same reason.
        if (head.status == StatusCode::OK || head.status == StatusCode::PARTIAL_CONTENT)
            && !conn_details.client.is_cleanup_synthetic()
        {
            metrics::VOLATILE_REFETCHED_OUTOFDATE.increment();
        }
        if head.status != StatusCode::NOT_MODIFIED {
            debug!(
                "File `{}` did not revalidate (status={})",
                file_path.display(),
                head.status
            );
        }
    }

    let plan = match plan_download(
        &head,
        ResumeState::new(resume_offset, resume_expected_total),
        conn_details.cached_flavor,
        cached,
        config.max_object_size,
    ) {
        Ok(plan) => plan,
        Err(anomaly) => {
            match anomaly {
                ResumeAnomaly::RangeIgnored => info!(
                    "Server returned 200 instead of 206 for resume of {} from mirror {}, starting fresh",
                    conn_details.debname, conn_details.mirror
                ),
                ResumeAnomaly::RangeNotSatisfiable => warn_once_or_info!(
                    "Server returned 416 for resume of {} from mirror {} (partial {}); discarding the stale partial and retrying fresh",
                    conn_details.debname,
                    conn_details.mirror,
                    HumanFmt::Size(resume_offset)
                ),
                ResumeAnomaly::ContentRangeMismatch => warn_once_or_info!(
                    "Invalid or mismatched Content-Range in 206 for {} from mirror {}; discarding the partial and retrying fresh",
                    conn_details.debname,
                    conn_details.mirror
                ),
            }
            partial.discard_resume().await;

            if anomaly.needs_refetch() {
                // Deliberately pass CacheFileStat::New here: the partial file
                // has been discarded, so from the upstream's perspective this
                // is a fresh unconditional fetch (no If-Modified-Since, no
                // If-None-Match, no Range).
                let retry_request =
                    build_fwd_request(&req_uri, host, &CacheFileStat::New, volatile_etag, 0, None);

                upstream_request_sent = PreciseInstant::now();
                fwd_response = match request_with_retry(&appstate.https_client, retry_request).await
                {
                    Ok((r, _parts)) => r,
                    Err(err) => return upstream_error_response(&err),
                };
                head = UpstreamHead::from_response(&fwd_response);
            }

            // A resume never revalidates: there is no cached copy to serve.
            plan_fresh_download(
                &head,
                conn_details.cached_flavor,
                None,
                config.max_object_size,
            )
        }
    };

    let (total_content_length, body_content_length, resume_offset) = match plan {
        DownloadPlan::NotModified((file, file_path)) => {
            if !conn_details.client.is_cleanup_synthetic() {
                metrics::VOLATILE_REFETCHED_UPTODATE.increment();
            }
            let file = touch_volatile_mtime(file, &file_path).await;

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
        DownloadPlan::Passthrough => {
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
                    "Request for file {} from mirror {} with URI `{req_uri}` failed with status {}",
                    conn_details.debname,
                    conn_details.mirror,
                    fwd_response.status()
                );
            } else {
                warn_once_or_info!(
                    "Request for file {} from mirror {} with URI `{req_uri}` failed with status {}; forwarding the response to the client",
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

            let body = rated_client_body(
                AccountedBody::new(
                    body,
                    Subject::Passthrough {
                        host: conn_details.mirror.format_authority().to_string(),
                        path: req_uri.path().to_owned(),
                        client: conn_details.client,
                        request_received_at: conn_details.request_received_at,
                        request_sent: upstream_request_sent,
                    },
                    |_| false,
                ),
                conn_details.client,
            );

            let mut response = Response::from_parts(parts, body);
            response
                .headers_mut()
                .append(VIA, HeaderValue::from_static(APP_VIA));

            trace!("Outgoing response: {response:?}");

            return response;
        }
        DownloadPlan::Reject(reason) => {
            reason.record_metrics();
            match reason {
                RejectReason::Unsolicited206 => warn_once_or_info!(
                    "Upstream returned 206 Partial Content without a Range request for {} from mirror {}; returning 502",
                    conn_details.debname,
                    conn_details.mirror
                ),
                RejectReason::InconsistentContentRange {
                    content_length,
                    span,
                } => warn_once_or_info!(
                    "Content-Length {content_length} disagrees with Content-Range span {span} for {} from mirror {}; returning 502",
                    conn_details.debname,
                    conn_details.mirror
                ),
                RejectReason::Oversize { total } => warn_once_or_info!(
                    "Upstream declared total size {} for file {} from mirror {}, exceeding `max_object_size`; returning 502",
                    HumanFmt::Size(total),
                    conn_details.debname,
                    conn_details.mirror
                ),
                RejectReason::NoContentLength => warn_once_or_info!(
                    "Upstream sent no usable Content-Length for file {} from mirror {}; returning 502",
                    conn_details.debname,
                    conn_details.mirror
                ),
                RejectReason::ZeroContentLength => warn_once_or_info!(
                    "Upstream declared Content-Length 0 for file {} from mirror {}; returning 502",
                    conn_details.debname,
                    conn_details.mirror
                ),
            }
            return quick_response(StatusCode::BAD_GATEWAY, reason.body());
        }
        DownloadPlan::Download {
            total,
            body,
            resume_offset,
        } => {
            if resume_offset > 0
                && let (ContentLength::Exact(total_nz), ContentLength::Exact(remaining_nz)) =
                    (total, body)
            {
                #[expect(clippy::cast_precision_loss, reason = "only for display purpose")]
                let remaining_percent = remaining_nz.get() as f32 / total_nz.get() as f32 * 100.0;
                info!(
                    "Resuming download of {} from mirror {} at {} ({} ({:.1}%) remaining of {} total)",
                    conn_details.debname,
                    conn_details.mirror,
                    HumanFmt::Size(resume_offset),
                    HumanFmt::Size(remaining_nz.get()),
                    remaining_percent,
                    HumanFmt::Size(total_nz.get())
                );
            }
            (total, body, resume_offset)
        }
    };

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
                    "Upstream mirror {} sent an invalid ETag `{etag}` for {}; discarding it",
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
                    "Upstream mirror {} sent an invalid Last-Modified `{lm}` for {}; discarding it",
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
                        "Failed to seek in partial file for {}; returning 500:  {}",
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
                    "Partial file size {current_size} != expected {resume_offset} for {} from mirror {} despite held fd; aborting the resume and returning 500",
                    conn_details.debname, conn_details.mirror
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
                        "Failed to create partial file `{}`; rejecting the request:  {}",
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
                        "Failed to create temporary file `{}`; rejecting the request:  {}",
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
        tokio::task::spawn(async move {
            download_file(
                &cd,
                warn_on_override,
                (body, body_content_length),
                (outfile, outpath),
                dbarrier,
                resume_offset,
                upstream_request_sent,
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
            "Failed to set TCP_NODELAY on the upstream tunnel to {host}:{port}; continuing with Nagle enabled:  {}",
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

    match tokio_nofollow_options().read(true).open(&cache_path).await {
        Ok(file) => {
            // CACHE_HITS only counts permanent-file hits; volatile hits live
            // in VOLATILE_HIT / VOLATILE_REFETCHED. Unconditional: in
            // sendfile builds only unaccounted requests reach hyper
            // (handed-off keep-alive connections bypass sendfile; sendfile
            // serves its own hits without hyper).
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
            // Unconditional miss accounting: in sendfile builds only
            // unaccounted requests reach hyper (sendfile's bumps are
            // splice-only, and handed-off keep-alive connections bypass
            // sendfile entirely).
            match conn_details.cached_flavor {
                CachedFlavor::Permanent => metrics::CACHE_MISSES.increment(),
                CachedFlavor::Volatile => {
                    // Cleanup-synthetic probes are operator bookkeeping, not
                    // user traffic — exclude them so the dashboard ratio
                    // reflects real client behavior only.
                    if !conn_details.client.is_cleanup_synthetic() {
                        metrics::VOLATILE_REFETCHED.increment();
                    }
                }
            }

            match appstate.active_downloads.insert(conn_details.key()) {
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
                    debug!(
                        "Serving file {} already in download from mirror {} for client {}...",
                        conn_details.debname, conn_details.mirror, conn_details.client
                    );
                    serve_downloading_file(conn_details, req, status, None).await
                }
                InsertOutcome::AtCapacity { max } => upstream_cap_rejection(&conn_details, max),
            }
        }
        Err(err) => {
            metrics::CACHE_IO_FAILURE.increment();
            error!(
                "Failed to open file `{}`; returning 500:  {}",
                cache_path.display(),
                ErrorReport(&err)
            );
            quick_response(StatusCode::INTERNAL_SERVER_ERROR, "Cache Access Failure")
        }
    }
}

#[must_use]
/// Answer a `CONNECT` whose client already passed the proxy-client ACL in
/// `preflight_method`.
fn connect_response(client: ClientInfo, req: Request<Incoming>) -> Response<ProxyCacheBody> {
    let config = global_config();

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

    // Shared with the sendfile/splice backend so tunnel policy stays identical
    // across backends; logs and policy metrics are bumped inside the validator.
    let (host, port) = match validate_connect_target(config, &client, req.uri()) {
        Ok(hp) => hp,
        Err(ConnectReject { status, msg }) => return quick_response(status, msg),
    };

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
                            "Failed to tunnel the connection for client {client} to {host}:{port}; closing the tunnel:  {}",
                            ErrorReport(&err)
                        );
                    }
                }
            }
            Err(err) => {
                metrics::TUNNEL_TRANSFER_FAILED.increment();
                error!(
                    "Failed to upgrade connection for client {client} to {host}:{port}; abandoning the tunnel:  {}",
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

    let acls = ClientAcls::from(global_config());

    match preflight_method(req.method().as_str(), &client, &acls) {
        Ok(RequestKind::Connect) => return connect_response(client, req),
        Ok(RequestKind::Get) => {}
        Err(reason) => {
            let (status, msg) = reason.response_parts();
            return quick_response(status, msg);
        }
    }

    let (requested_host, requested_port) = match preflight_target(
        req.uri(),
        req.version() == http::Version::HTTP_11,
        || req.headers().contains_key(HOST),
        &client,
        &acls,
    ) {
        Ok(RequestTarget::Proxy { host, port }) => (host, port),
        Ok(RequestTarget::WebUi) => {
            return serve_web_interface(req.uri(), &appstate)
                .await
                .into_hyper_response();
        }
        Err(reason) => {
            let (status, msg) = reason.response_parts();
            return quick_response(status, msg);
        }
    };

    let requested_host = match authorize_cache_access(&client, requested_host) {
        Ok(rh) => rh,
        Err((status, msg)) => return quick_response(status, msg),
    };

    if req.body().size_hint().exact() != Some(0) {
        // Also fires for unknown-length bodies, whose lower bound can be 0.
        warn_once_or_info!(
            "Request from client {client} has a body (at least {} bytes); not forwarding it: {} {}",
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
    ) && let Some(moved_uri) =
        parse_redirect_location(&fwd_response, requested_host.as_str(), parts.uri.path())
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

            let body = rated_client_body(
                AccountedBody::new(
                    body,
                    Subject::Passthrough {
                        host: requested_host.to_string(),
                        path: request_path.clone(),
                        client,
                        request_received_at: passthrough_request_received_at,
                        request_sent: redirected_request_sent,
                    },
                    |_| false,
                ),
                client,
            );

            let mut response = Response::from_parts(parts, body);
            response
                .headers_mut()
                .append(VIA, HeaderValue::from_static(APP_VIA));

            trace!("Outgoing response: {response:?}");

            return response;
        } else if moved_uri.scheme().is_none() {
            // A relative Location (`/pool/...`) is legal per RFC 9110, but this
            // backend only follows absolute targets. Reported before the scheme
            // branch below, which would otherwise call it an unsupported scheme.
            debug!("Moved URI `{moved_uri}` is relative; not following the redirect");
        } else if moved_uri.scheme().is_none_or(|scheme| {
            *scheme != http::uri::Scheme::HTTP && *scheme != http::uri::Scheme::HTTPS
        }) {
            debug!("Scheme of moved URI `{moved_uri}` not supported");
        } else if let Some(moved_host) = moved_uri.host() {
            debug!("Host `{moved_host}` of moved URI not permitted");
        } else {
            debug!("Moved URI has no host; not following the redirect");
        }
    }

    let (parts, body) = fwd_response.into_parts();

    let body = rated_client_body(
        AccountedBody::new(
            body,
            Subject::Passthrough {
                host: requested_host.to_string(),
                path: request_path,
                client,
                request_received_at: passthrough_request_received_at,
                request_sent: fwd_request_sent,
            },
            |_| false,
        ),
        client,
    );

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
    T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
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
            info!(
                "Closing connection to client {client} after a rate timeout:  {}",
                ErrorReport(perr)
            );
        } else {
            error!(
                "Failed to serve connection for client {client}; closing the connection:  {}",
                ErrorReport(&err)
            );
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
