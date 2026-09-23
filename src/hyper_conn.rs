//! Hyper client backend: the full request pipeline (pre-flight, dispatch,
//! cache lookup, upstream fetch, simple proxy) for every request it parses
//! itself, and the resumption point for requests the sendfile backend has
//! already classified.
//!
//! `handle_hyper_connection` takes an `Option<HandoffPlan>` from
//! `sendfile_conn`; the plan applies to the first request on the connection
//! only (see [`HandoffPlan`] for the pairing invariant and the pipeline stage
//! each variant enters).  Later keep-alive requests run the full pipeline
//! here.

use std::{
    borrow::Cow, convert::Infallible, fmt, num::NonZero, os::unix::fs::MetadataExt as _,
    path::Path, path::PathBuf, sync::Arc,
};

use futures_util::StreamExt as _;
use http::{
    HeaderName, HeaderValue, Method, Request, Response, StatusCode, Uri,
    header::{
        ACCEPT, CACHE_CONTROL, CONNECTION, CONTENT_TYPE, ETAG, HOST, IF_MODIFIED_SINCE,
        IF_NONE_MATCH, IF_RANGE, LAST_MODIFIED, LOCATION, RANGE, USER_AGENT, VIA,
    },
    uri::{Authority, PathAndQuery},
};
use http_body::{Body, Frame};
use http_body_util::{BodyExt as _, Empty, combinators::BoxBody};
use hyper::{body::Incoming, server::conn::http1, service::service_fn};
use hyper_util::{client::legacy::connect::HttpConnector, rt::tokio::TokioIo};
use tokio::io::{AsyncReadExt as _, AsyncSeekExt as _, AsyncWriteExt as _};
use tracing::{debug, error, info, trace, warn};

use crate::{
    AppState, Never, Scheme,
    accounted_body::{AccountedBody, Subject},
    active_downloads::{
        ActiveDownloadStatus, AttachedReaderState, Declined, InsertOutcome, Origination, Serveable,
        await_serveable,
    },
    build_info::{APP_USER_AGENT, APP_VIA},
    cache_conditional::{CacheInfo, RangeRequestHeaders, ServeParams, ServePlan},
    cache_layout::{CacheMiss, CachedFlavor, ConnectionDetails},
    cache_metadata::{
        self, InvalidValidator, UpstreamMetadata, check_upstream_validators,
        write_upstream_metadata,
    },
    cache_quota::QuotaExceeded,
    channel_body::{ChannelBody, ChannelEvent},
    client_info::ClientInfo,
    config::ClientHost,
    connect_tunnel::{
        ConnectReject, copy_bidirectional_idle, report_tunnel_outcome, validate_connect_target,
    },
    content_type::{content_type_for_cached_file, warn_on_content_type_mismatch},
    database_task::{DatabaseCommand, DbCmdTransfer, TransferKind, send_db_command},
    deb_mirror::{Origin, OriginSighting},
    delivery::{Mechanism, Role},
    error::{
        ErrorReport, UpstreamFetchError, is_io_timed_out_in_chain, is_peer_disconnect,
        is_tls_certificate_rejection,
    },
    fs_open::{
        CacheAccessFailure, hint_sequential_read, regular_file_metadata, tokio_nofollow_options,
        touch_volatile_mtime,
    },
    global_cache_quota, global_config, global_verify_throttle, global_webif_hosts,
    guards::{Consequence, DownloadBarrier, InitBarrier, Settled},
    humanfmt::HumanFmt,
    integrity::note_cached_index_touch,
    limits::VOLATILE_CACHE_MAX_AGE,
    log_once, metrics,
    parallel_hack::{NUDGE_BODY, log_nudge, nudge_head, should_nudge},
    partial_file::{self, TempPath},
    passthrough_limiter,
    permitted_host_cache::{authorize_cache_access, is_host_allowed_cached},
    precise_instant::PreciseInstant,
    proxy_body::{ProxyCacheBody, full_body, quick_response, quick_response_closing},
    rate_checked_body::{ClientBody, MaybeRated, RateCheckedBodyErr},
    rate_log,
    request_dispatch::{
        ClientAcls, DispatchOutcome, PassthroughReason, RejectReason, RequestKind, RequestTarget,
        dispatch_request, preflight_method, preflight_target, preflight_via,
    },
    response_head::{ResponseHead, ResponseKind, retry_after_secs},
    scheme_cache::{self, SchemeDecision},
    static_assert,
    transfer_error::{CacheError, DeliveryFailure, DownloadFailure, InternalError, UpstreamError},
    tunnel_limiter,
    upstream_head::{
        ContentLength, DownloadPlan, RejectGates, ResumeAnomaly, ResumeState, UpstreamHead,
        plan_download, plan_fresh_download,
    },
    upstream_retry::{self, RetryStop},
    warn_once_or_debug, warn_once_or_info,
    web::serve_web_interface,
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

/// The canonical `500` for a cache-file access failure.  The failure itself
/// is logged (and `CACHE_IO_FAILURE`/`CACHE_NON_REGULAR`-counted) at the site
/// that detected it; this only fixes the one status/body pair every such site
/// answers with.
#[must_use]
fn cache_access_failure() -> Response<ProxyCacheBody> {
    quick_response(StatusCode::INTERNAL_SERVER_ERROR, "Cache Access Failure")
}

/// Why a [`request_with_retry`] call failed.
#[derive(Debug, thiserror::Error)]
enum RequestError {
    /// The client's transport error.
    #[error(transparent)]
    Transport(#[from] hyper_util::client::legacy::Error),
    /// A scheme rewrite produced parts `Uri::from_parts` refuses.
    #[error("failed to rebuild the request URI for a scheme change")]
    InvalidUri(#[source] http::uri::InvalidUriParts),
}

/// The fields of a [`RequestFailure`], separated only so the payload can be
/// boxed behind it.
#[derive(Debug)]
struct FailedRequest {
    error: RequestError,
    /// The URI of the *last* attempt, not the one the caller handed in: the
    /// scheme cache rewrites the scheme inside the retry loop (the https
    /// upgrade probe, and the revert back to the original scheme), so a
    /// caller-side copy would name a URL the proxy never dialled.
    uri: Uri,
    attempts: u32,
    limit: Option<RetryStop>,
}

/// A terminal [`request_with_retry`] failure carrying the retry context and
/// the request identity its report needs. `limit` is `Some` only when the
/// connect-retry loop ran out of budget, which is exactly what separates a
/// [`Phase::Connect`] failure from a head-phase transport failure — so the
/// phase is derived here once instead of being guessed at every call site.
///
/// The payload is boxed because it is well past `clippy::result_large_err`'s
/// threshold and would otherwise widen every `request_with_retry` `Result`,
/// success path included.
///
/// [`Phase::Connect`]: crate::transfer_error::Phase::Connect
#[derive(Debug)]
pub(crate) struct RequestFailure(Box<FailedRequest>);

impl fmt::Display for RequestFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Every report of this error already names the failed request, so
        // this layer only adds the retry context an exhausted connect loop
        // has and a head-phase transport failure has not.
        let FailedRequest {
            error: _,
            uri: _,
            attempts,
            limit,
        } = &*self.0;
        f.write_str("upstream request")?;
        if let Some(limit) = limit {
            write!(f, " after {attempts} connection attempts ({limit})")?;
        }
        Ok(())
    }
}

impl std::error::Error for RequestFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.0.error)
    }
}

impl RequestFailure {
    fn new(failed: FailedRequest) -> Self {
        Self(Box::new(failed))
    }

    /// A scheme rewrite produced parts `Uri::from_parts` refuses.  The
    /// pre-flight admits only targets with an absolute path, so this is a
    /// defensive answer rather than a reachable one: it fails the request
    /// instead of panicking the task, which the release profile's
    /// `panic = 'abort'` turns into a daemon exit.
    fn invalid_uri(error: http::uri::InvalidUriParts, uri: Uri, attempts: u32) -> Self {
        Self::new(FailedRequest {
            error: RequestError::InvalidUri(error),
            uri,
            attempts,
            limit: None,
        })
    }

    /// The URI of the attempt that failed, after any scheme rewrite.
    fn uri(&self) -> &Uri {
        &self.0.uri
    }

    /// An exhausted connect budget is a connect-phase failure; anything else
    /// happened once a connection was up, so it is a head-phase transport
    /// failure. Both phases are once-gated by the download runner.
    pub(crate) fn into_upstream(self, operation: &'static str) -> UpstreamError {
        let FailedRequest {
            error,
            uri,
            attempts,
            limit,
        } = *self.0;
        match limit {
            Some(limit) => {
                UpstreamError::connect(operation, std::io::Error::other(error), attempts, limit)
            }
            None => UpstreamError::head_transport(operation, error),
        }
        .with_target(uri.to_string())
    }
}

/// On success the request `Parts` are handed back alongside the response —
/// they were consumed by the request anyway, and returning them lets the
/// rare redirect-follow path rebuild a request without the caller cloning
/// the whole `HeaderMap` up front.
pub(crate) async fn request_with_retry(
    client: &HttpClient,
    request: Request<Empty<bytes::Bytes>>,
) -> Result<(Response<Incoming>, http::request::Parts), RequestFailure> {
    // Auto-mode's HTTPS-upgrade revert branch only fires once `attempt`
    // has crossed this threshold; below it, transient connect errors
    // retry without reverting the scheme.
    const HTTPS_UPGRADE_REVERT_AFTER_ATTEMPTS: u32 = 2;
    // The Always-mode terminal-failure HTTPS_UPGRADE_FAILED bump below
    // (gated on an exhausted retry budget while still probing) relies on the
    // Auto-mode revert firing first. If MAX_ATTEMPTS were ever
    // <= HTTPS_UPGRADE_REVERT_AFTER_ATTEMPTS, Auto mode would also fall
    // through there still probing and bump HTTPS_UPGRADE_FAILED
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

    // Host names are case-insensitive: key the scheme cache, and the
    // `http_only_mirrors` match `scheme_cache::resolve` does, on the lowercase
    // host every other part of the proxy uses (`ClientHost`), as the splice
    // backend's `Mirror` key already is. The raw spelling of a client URI or
    // a redirect `Location` would miss an http-only entry and grow one cache
    // entry per casing.
    if let Some(auth) = parts.uri.authority()
        && auth.host().bytes().any(|b| b.is_ascii_uppercase())
    {
        let host = auth.host().to_ascii_lowercase();
        let lowered = match auth.port_u16() {
            Some(port) => format!("{host}:{port}"),
            None => host,
        };
        let mut uri_parts = parts.uri.into_parts();
        uri_parts.authority =
            Some(Authority::try_from(lowered).expect("lowercasing keeps the authority valid"));
        parts.uri = Uri::from_parts(uri_parts).expect("valid parts");
    }

    let orig_scheme = parts.uri.scheme().cloned();

    let mut probe = UpgradeProbe::NotProbing;

    if let Some(os) = &orig_scheme
        && *os != http::uri::Scheme::HTTP
    {
        // A non-HTTP original scheme (e.g. an explicit https:// proxied URL) is
        // left untouched; the scheme cache is hyper-specifically not consulted.
        debug!("Not altering {os} scheme for request {}", parts.uri);
    } else if let Some(auth) = parts.uri.authority() {
        let decision = scheme_cache::resolve(auth.into(), global_config());
        let upgrade = UpgradeProbe::of(decision);
        let scheme = if upgrade.is_probing() {
            debug!(
                "No cached scheme for host {auth}, trying https upgrade from original scheme {orig_scheme:?}..."
            );
            http::uri::Scheme::HTTPS
        } else {
            let scheme = decision
                .fixed_scheme()
                .expect("non-upgrade decision has a fixed scheme");
            debug!("Using {scheme} scheme for host {auth}, original scheme is {orig_scheme:?}");
            scheme.into()
        };
        let mut uri_parts = parts.uri.clone().into_parts();
        uri_parts.scheme = Some(scheme);
        // `auth` is last used above; NLL ends its borrow so `parts.uri` can be replaced.
        parts.uri = match Uri::from_parts(uri_parts) {
            Ok(uri) => uri,
            Err(err) => {
                metrics::UPSTREAM_HYPER_REQUEST_FAILED.increment();
                return Err(RequestFailure::invalid_uri(err, parts.uri, 0));
            }
        };
        // Counted only once the upgrade is really attempted, so the
        // ATTEMPTED == SUCCEEDED + REVERTED + FAILED identity holds.
        if upgrade.is_probing() {
            metrics::HTTPS_UPGRADE_ATTEMPTED.increment();
        }
        probe = upgrade;
    }

    #[expect(
        clippy::items_after_statements,
        reason = "keep definition before grouped call sites"
    )]
    async fn inner_loop(
        client: &HttpClient,
        mut parts: http::request::Parts,
        orig_scheme: Option<http::uri::Scheme>,
        mut probe: UpgradeProbe,
    ) -> Result<(Response<Incoming>, http::request::Parts), RequestFailure> {
        let mut backoff = upstream_retry::Backoff::new(
            global_config().upstream_retry_budget,
            coarsetime::Instant::now(),
        );

        loop {
            let req_clone = Request::from_parts(parts.clone(), Empty::new());

            let _: Never = match client.request(req_clone).await {
                Ok(response) => {
                    if probe.is_probing() {
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
                    if probe.is_probing() {
                        // Non-connect transport error (e.g. read timeout,
                        // request framing) terminates the request without
                        // retry. Count the upgrade attempt as failed so the
                        // ATTEMPTED == SUCCEEDED + REVERTED + FAILED identity
                        // holds.
                        metrics::HTTPS_UPGRADE_FAILED.increment();
                    }
                    return Err(RequestFailure::new(FailedRequest {
                        error: err.into(),
                        uri: parts.uri,
                        attempts: backoff.attempt(),
                        limit: None,
                    }));
                }
                Err(err) => {
                    if is_io_timed_out_in_chain(&err) {
                        metrics::HTTP_TIMEOUT_UPSTREAM_CONNECT.increment();
                    }
                    let attempt = backoff.attempt();
                    // A rejected certificate is what an interceptor presents:
                    // never a reason to revert to plain HTTP, and repeated
                    // identically by every retry, so it ends the loop at once.
                    let certificate_rejected = is_tls_certificate_rejection(&err);
                    if !certificate_rejected
                        && attempt > HTTPS_UPGRADE_REVERT_AFTER_ATTEMPTS
                        && probe == UpgradeProbe::Revertible
                    {
                        debug!(
                            "Https upgrade failed for host {} after {attempt} connection attempts, re-trying with original scheme {orig_scheme:?}...",
                            parts
                                .uri
                                .authority()
                                .expect("authority must exist for a https upgrade")
                        );

                        // reset https upgrade
                        let mut uri_parts = parts.uri.clone().into_parts();
                        uri_parts.scheme.clone_from(&orig_scheme);
                        parts.uri = match Uri::from_parts(uri_parts) {
                            Ok(uri) => uri,
                            Err(err) => {
                                metrics::UPSTREAM_HYPER_REQUEST_FAILED.increment();
                                metrics::HTTPS_UPGRADE_FAILED.increment();
                                return Err(RequestFailure::invalid_uri(err, parts.uri, attempt));
                            }
                        };
                        metrics::HTTPS_UPGRADE_REVERTED.increment();
                        probe = UpgradeProbe::NotProbing;
                        backoff.reset_delay();
                        // The revert iteration is another upstream attempt
                        // even though the retry budget is not consumed for it.
                        // Match `Backoff::next_retry` in counting it as a retry.
                        metrics::UPSTREAM_RETRIES.increment();
                        continue;
                    }

                    let next = if certificate_rejected {
                        None
                    } else {
                        backoff.next_retry(coarsetime::Instant::now())
                    };
                    let Some(delay) = next else {
                        metrics::UPSTREAM_HYPER_REQUEST_FAILED.increment();
                        if probe.is_probing() {
                            // Terminal connect failure while still probing:
                            // in Always mode the revert branch above is gated
                            // off, so the only outcome of an attempted upgrade
                            // is failure here. Keep the
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

                        let limit = if certificate_rejected {
                            RetryStop::Permanent
                        } else {
                            backoff.limit().into()
                        };
                        debug!(
                            "Upstream retries ended after {attempt} connection attempts ({limit})"
                        );
                        return Err(RequestFailure::new(FailedRequest {
                            error: err.into(),
                            uri: parts.uri,
                            attempts: attempt,
                            limit: Some(limit),
                        }));
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

    if probe.is_probing() {
        let client = client.clone();

        // Spawn a new task such that even if the client disconnects,
        // the task will continue to run and initialize the scheme cache.
        tokio::task::spawn(async move {
            let result = inner_loop(&client, parts, orig_scheme, probe).await;
            if let Err(ref err) = result {
                // The caller owns the terminal failure report. This background
                // task only records scheme initialization context.
                debug!(
                    "Failed to initialize scheme cache for host {} in background task:  {}",
                    err.uri()
                        .authority()
                        .expect("authority exists in case of https upgrade test"),
                    ErrorReport(err)
                );
            }
            result
        })
        .await
        .expect("task should not panic")
    } else {
        inner_loop(client, parts, orig_scheme, UpgradeProbe::NotProbing).await
    }
}

/// Synthetic `502 Bad Gateway` for an upstream-fetch failure, carrying the real
/// transport reason as an `http::Extensions` value so an internal caller (cleanup)
/// can recover it instead of seeing only the laundered status. Real clients ignore
/// the extension (it is never serialised to the wire). Registered downloads
/// report through their guard; this adapter owns unregistered passthrough failures.
#[must_use]
fn upstream_error_response(err: &RequestFailure) -> Response<ProxyCacheBody> {
    warn_once_or_info!(
        "Upstream request to {} failed; returning 502:  {}",
        err.uri(),
        ErrorReport(err)
    );
    let mut response = quick_response(StatusCode::BAD_GATEWAY, "Upstream Error");
    response.extensions_mut().insert(UpstreamFetchError {
        reason: ErrorReport(err).to_string(),
    });
    response
}

/// Whether an upstream request is an HTTPS-upgrade probe, and whether it may
/// fall back to the original scheme.  "Revertible" is only meaningful for a
/// probe, so the two live in one value instead of two booleans that can
/// disagree.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum UpgradeProbe {
    /// Not an upgrade attempt: the scheme is fixed (cached, configured, or
    /// the one the client asked for).
    NotProbing,
    /// `Auto` mode with no cached scheme: revert to the original scheme once
    /// the connect attempts cross `HTTPS_UPGRADE_REVERT_AFTER_ATTEMPTS`,
    /// unless the upstream's certificate was rejected, which is terminal.
    /// `scheme_cache::decide` only reaches it when no cached scheme exists,
    /// so nothing is lost by reverting.
    Revertible,
    /// `Always` mode: an upgrade attempt with no fallback.
    Committed,
}

impl UpgradeProbe {
    /// The probe a resolved scheme decision starts its request with.
    const fn of(decision: SchemeDecision) -> Self {
        match decision {
            SchemeDecision::Http | SchemeDecision::Https => Self::NotProbing,
            SchemeDecision::AutoUpgrade => Self::Revertible,
            SchemeDecision::AlwaysUpgrade => Self::Committed,
        }
    }

    const fn is_probing(self) -> bool {
        match self {
            Self::NotProbing => false,
            Self::Revertible | Self::Committed => true,
        }
    }
}

/// Put the accounting owner outside both source and downstream-rate adapters.
fn rated_client_body<B>(body: B, subject: Subject) -> ProxyCacheBody
where
    B: Body<Data = bytes::Bytes> + Send + Sync + 'static,
    B::Error: Into<DeliveryFailure>,
{
    let config = global_config();
    let rated = ClientBody::new(body, config.min_download_rate, config.rate_check_timeframe);
    ProxyCacheBody::Boxed(BoxBody::new(AccountedBody::new(rated, subject)))
}

/// Cache reading establishes both the I/O source and the promised-length
/// contract before the body reaches generic delivery accounting.
struct CachedFileBody {
    reader: tokio_util::io::ReaderStream<tokio::io::Take<tokio::fs::File>>,
    path: PathBuf,
    remaining: u64,
    terminal: bool,
}

impl CachedFileBody {
    fn new(file: tokio::fs::File, length: u64, capacity: usize, path: PathBuf) -> Self {
        Self {
            reader: tokio_util::io::ReaderStream::with_capacity(file.take(length), capacity),
            path,
            remaining: length,
            terminal: false,
        }
    }
}

impl Body for CachedFileBody {
    type Data = bytes::Bytes;
    type Error = CacheError;

    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        use std::task::Poll;
        if self.is_end_stream() {
            return Poll::Ready(None);
        }
        match self.reader.poll_next_unpin(cx) {
            Poll::Ready(Some(Ok(bytes))) => {
                self.remaining -= bytes.len() as u64;
                Poll::Ready(Some(Ok(Frame::data(bytes))))
            }
            Poll::Ready(Some(Err(error))) => {
                self.terminal = true;
                Poll::Ready(Some(Err(CacheError::counted_io(
                    "read cached file",
                    &self.path,
                    error,
                ))))
            }
            Poll::Ready(None) => {
                self.terminal = true;
                // A short file is a consistency anomaly with no failed
                // syscall behind it, so no `CACHE_IO_FAILURE`: the same
                // treatment `channel_body.rs` and sendfile's unexpected-EOF
                // arm give it.
                Poll::Ready(Some(Err(CacheError::invalid(
                    "read cached file",
                    format!(
                        "file shorter than promised ({} bytes missing)",
                        self.remaining
                    ),
                ))))
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn size_hint(&self) -> http_body::SizeHint {
        http_body::SizeHint::with_exact(self.remaining)
    }

    fn is_end_stream(&self) -> bool {
        self.terminal || self.remaining == 0
    }
}

/// Hyper is the only source of these erased transport errors. Restore upstream
/// provenance here; library error-chain inspection never reaches a delivery logger.
fn upstream_body_error(error: hyper::Error) -> UpstreamError {
    if is_io_timed_out_in_chain(&error) {
        metrics::HTTP_TIMEOUT_UPSTREAM_READ.increment();
    }
    metrics::UPSTREAM_HYPER_BODY_ERR.increment();
    UpstreamError::transport("read upstream response body", error)
}

/// Finish an uncached passthrough: account the upstream body, apply the
/// client rate check and append our `Via`.  The three passthrough sites (a
/// fetch the cache pipeline declined, and the simple proxy with and without a
/// followed redirect) differ only in the [`Subject`].
#[must_use]
fn passthrough_response(
    response: Response<Incoming>,
    subject: Subject,
) -> Response<ProxyCacheBody> {
    let (parts, body) = response.into_parts();

    let body = rated_client_body(
        body.map_err(|error| DeliveryFailure::Upstream(upstream_body_error(error))),
        subject,
    );

    let mut response = Response::from_parts(parts, body);
    response
        .headers_mut()
        .append(VIA, HeaderValue::from_static(APP_VIA));

    trace!("Outgoing response: {response:?}");

    response
}

#[must_use]
#[expect(
    clippy::unused_async,
    reason = "regular_file_metadata went synchronous; the sole caller awaits \
              this in an async match arm alongside other async branches, so \
              staying async keeps the call site uniform"
)]
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

    let md = match regular_file_metadata(&file, &file_path) {
        Ok(data) => data,
        Err(CacheAccessFailure(_)) => {
            return cache_access_failure();
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

    // The feeder owns no delivery counters or summaries: queued bytes have
    // not yet been consumed by Hyper. The outer body owns that progress.
    tokio::task::spawn(async move {
        hint_sequential_read(&file, u64::MAX, &file_path);
        let result = async {
            let mut draining = false;
            loop {
                loop {
                    let mut buffer = bytes::BytesMut::with_capacity(config.buffer_size);
                    let count = file.read_buf(&mut buffer).await.map_err(|error| {
                        CacheError::counted_io("read growing cache file", &file_path, error)
                    })?;
                    if count == 0 {
                        break;
                    }
                    tx.send(ChannelEvent::Data(buffer.freeze()))
                        .await
                        .map_err(|_closed| DeliveryFailure::Cancelled)?;
                }
                if draining {
                    return Ok(());
                }
                if receiver.changed().await.is_err() {
                    let state = status.read().await.attached_reader();
                    match state {
                        AttachedReaderState::Drainable => draining = true,
                        AttachedReaderState::Failed(failure) => {
                            return Err(DeliveryFailure::Download(failure));
                        }
                        AttachedReaderState::Incomplete => {
                            return Err(InternalError::invalid(
                                "follow growing cache file",
                                "download progress closed in nonterminal state",
                            )
                            .into());
                        }
                    }
                }
            }
        }
        .await;
        let _sent = tx.send(ChannelEvent::Finished(result)).await;
    });

    let head = ResponseHead {
        content_length: match content_length {
            ContentLength::Exact(size) => Some(size.get()),
            ContentLength::Unknown(_) => None,
        },
        content_type: Some(content_type),
        accept_ranges: true,
        last_modified: Some(&last_modified_str),
        etag: file_etag.as_deref(),
        age: Some(age),
        ..ResponseHead::bare(StatusCode::OK, ResponseKind::Success)
    };

    let body = rated_client_body(
        ChannelBody::new(rx, content_length),
        Subject::Cached {
            conn_details,
            mechanism: Mechanism::Channel,
            size: match content_length {
                ContentLength::Exact(size) => Some(size.get()),
                ContentLength::Unknown(_) => None,
            },
            role: Role::LateJoiner,
            partial: false,
        },
    );

    let response = head.into_hyper(body);

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
    let aliased = conn_details.alias_suffix();

    let mdata = match prefetched_local_metadata {
        Some(m) => {
            debug_assert!(
                m.file_type().is_file(),
                "prefetched_local_metadata must be a regular file; caller is responsible for the type check"
            );
            m
        }
        None => match regular_file_metadata(&file, &file_path) {
            Ok(m) => m,
            Err(CacheAccessFailure(_)) => {
                return cache_access_failure();
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

            let head = ResponseHead::not_modified(
                &cache_info.last_modified_str,
                cache_info.file_etag.as_deref(),
                cache_info.age,
            );
            let response = head.into_hyper(empty_body());

            trace!("Outgoing response: {response:?}");

            return response;
        }
        ServePlan::NotSatisfiable => {
            return ResponseHead::range_not_satisfiable(file_size).into_hyper(empty_body());
        }
    };

    // The file is streamed straight through; let the kernel grow its
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

    // Every caller hands over a file freshly opened for this response, so at
    // `start == 0` (the whole-file case, i.e. every non-Range request) the
    // descriptor already sits where the seek would put it. tokio's `seek`
    // is a blocking-pool round trip, so skipping it drops a `spawn_blocking`
    // handoff from the common cache hit.
    #[cfg(debug_assertions)]
    {
        let position = tokio::io::AsyncSeekExt::stream_position(&mut file).await;
        debug_assert!(
            matches!(position, Ok(0)),
            "callers must hand over a freshly opened cache file positioned at 0"
        );
    }
    if start != 0
        && let Err(err) = file.seek(std::io::SeekFrom::Start(start)).await
    {
        metrics::CACHE_IO_FAILURE.increment();
        error!(
            "Failed to seek cached file `{}` to offset {start}/{file_size}; returning 500:  {}",
            file_path.display(),
            ErrorReport(&err)
        );
        return cache_access_failure();
    }

    let content_type = content_type_for_cached_file(&conn_details.debname);

    // Bound the reader to the (possibly range-trimmed) content length: an
    // unbounded stream over-reads past a closed range's end, and the surplus
    // makes AccountedBody's Drop accounting see transferred != size —
    // logging a spurious "Aborted serving" warn and skipping the SERVED_*
    // metrics and delivery DB row for a request that was actually served
    // fully.
    let body = rated_client_body(
        CachedFileBody::new(file, content_length, config.buffer_size, file_path),
        Subject::Cached {
            conn_details,
            mechanism: Mechanism::Stream,
            size: Some(content_length),
            role: Role::Cached,
            partial: params.is_partial(),
        },
    );

    // TODO: use become: https://github.com/rust-lang/rust/issues/112788
    serve_cached_file_response(cache_info, params, content_type, body)
}

/// Response builder of `serve_cached_file_buf`; always called as a tail
/// call.
fn serve_cached_file_response(
    cache_info: &CacheInfo,
    params: ServeParams,
    content_type: &'static str,
    body: ProxyCacheBody,
) -> Response<ProxyCacheBody> {
    let http_status = params.http_status();
    let ServeParams {
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

    let head = ResponseHead {
        content_length: Some(content_length),
        content_type: Some(content_type),
        accept_ranges: true,
        last_modified: Some(&cache_info.last_modified_str),
        etag: cache_info.file_etag.as_deref(),
        age: Some(cache_info.age),
        content_range: content_range.map(Cow::Owned),
        ..ResponseHead::bare(http_status, ResponseKind::Success)
    };

    let response = head.into_hyper(body);

    trace!("Outgoing response of cached file: {response:?}");

    response
}

/// `req` is borrowed, not consumed: this call sits at the tail of
/// [`serve_new_file_worker`], whose future is already close to
/// `clippy::large_futures` (see its definition). Moving the request in would
/// store it inline in that future for the whole upstream exchange -- measured
/// at 864 bytes -- for a value only `serve_cached_file` ever reads, and by
/// reference. The other two callers own their request and simply lend it.
#[must_use]
async fn serve_downloading_file(
    conn_details: ConnectionDetails,
    req: &Request<Empty<()>>,
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
            serve_cached_file(conn_details, req, file, path, meta.as_deref(), None).await
        }
        Err(failure) => {
            drop(status);
            let (status_code, msg) = failure.response_parts();
            let head = ResponseHead {
                retry_after: failure.retry_after().map(retry_after_secs),
                ..ResponseHead::error(status_code)
            };
            head.into_hyper(full_body(msg))
        }
    }
}

enum CacheFileStat {
    Volatile {
        file: tokio::fs::File,
        file_path: PathBuf,
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
        conn_details.cached_flavor(),
        CachedFlavor::Volatile,
        "serve_volatile_file() assumes volatile flavor"
    );

    let mdata = match regular_file_metadata(&file, &file_path) {
        Ok(data) => data,
        Err(CacheAccessFailure(_)) => {
            return cache_access_failure();
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

            // Lookup-site accounting (see `process_cache_request`).
            // Cleanup-synthetic probes (task_cleanup's `.xz -> .gz -> raw`
            // walk) would inflate the user-facing counter - exclude them.
            if !conn_details.client.is_cleanup_synthetic() {
                metrics::VOLATILE_HIT.increment();
            }

            note_cached_index_touch(&conn_details, req.uri().path(), &file_path);
            return serve_cached_file(conn_details, &req, file, file_path, None, Some(mdata)).await;
        }
    } else {
        warn_once_or_info!(
            "Volatile file `{}` was modified in the future; treating it as stale and refetching from upstream",
            file_path.display()
        );
    }

    // Lookup-site parent refetch bump; dominates the VOLATILE_REFETCHED_*
    // subset bumps in `serve_new_file`. Cleanup-synthetic probes are
    // operator bookkeeping, not user traffic - exclude them so the
    // dashboard ratio reflects real client behavior only.
    if !conn_details.client.is_cleanup_synthetic() {
        metrics::VOLATILE_REFETCHED.increment();
    }

    serve_cache_miss(
        conn_details,
        req,
        file_path,
        CacheMiss::StaleVolatile {
            file,
            size: mdata.size(),
        },
        appstate,
    )
    .await
}

/// Fetch (or join the in-flight fetch of) a resource whose cache lookup
/// produced `miss`.
///
/// Hit/miss/refetch accounting is the lookup site's job and has already
/// happened - in [`process_cache_request`] / [`serve_volatile_file`] for
/// requests hyper looked up itself, in `sendfile_conn::try_sendfile_request`
/// for a `HandoffPlan::CacheMiss` - so nothing is bumped here.
async fn serve_cache_miss(
    conn_details: ConnectionDetails,
    req: Request<Empty<()>>,
    cache_path: PathBuf,
    miss: CacheMiss,
    appstate: AppState,
) -> Response<ProxyCacheBody> {
    match appstate.active_downloads.insert(conn_details.key()) {
        InsertOutcome::Originator(origination) => {
            let cfstate = match miss {
                CacheMiss::NotFound => {
                    trace!(
                        "File {} not found, serving new version...",
                        cache_path.display()
                    );
                    CacheFileStat::New
                }
                CacheMiss::StaleVolatile { file, size } => CacheFileStat::Volatile {
                    file,
                    file_path: cache_path,
                    prev_size: size,
                },
            };
            serve_new_file(conn_details, origination, req, cfstate, appstate).await
        }
        InsertOutcome::Joined { status } => {
            match miss {
                CacheMiss::NotFound => {
                    trace!(
                        "File {} not found, serving in-download version...",
                        cache_path.display()
                    );
                    debug!(
                        "Serving file {} already in download from mirror {} for client {}...",
                        conn_details.debname, conn_details.mirror, conn_details.client
                    );
                }
                CacheMiss::StaleVolatile { .. } => {
                    debug!(
                        "Serving file {} already in cache / download from mirror {} for client {}...",
                        conn_details.debname, conn_details.mirror, conn_details.client
                    );
                }
            }
            serve_downloading_file(conn_details, &req, status, None).await
        }
        InsertOutcome::AtCapacity { max } => upstream_cap_rejection(&conn_details, max),
    }
}

/// Cache operation adapter shared by the worker and its salvage path.
struct DownloadWriter<'a> {
    writer: tokio::io::BufWriter<tokio::fs::File>,
    path: &'a Path,
}

impl DownloadWriter<'_> {
    async fn write(&mut self, mut chunk: bytes::Bytes) -> Result<(), CacheError> {
        self.writer
            .write_all_buf(&mut chunk)
            .await
            .map_err(|error| CacheError::counted_io("write download cache file", self.path, error))
    }

    async fn flush(&mut self) -> Result<(), CacheError> {
        self.writer
            .flush()
            .await
            .map_err(|error| CacheError::counted_io("flush download cache file", self.path, error))
    }
}

async fn download_file_worker(
    body: &mut MaybeRated<Incoming>,
    writer: &mut DownloadWriter<'_>,
    content_length: ContentLength,
    bytes: &mut u64,
    barrier: &mut DownloadBarrier,
) -> Result<PreciseInstant, DownloadFailure> {
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|error| match *error {
            RateCheckedBodyErr::RateTimeout(rate) => UpstreamError::rate(rate),
            RateCheckedBodyErr::Inner(error) => upstream_body_error(error),
        })?;
        if let Ok(chunk) = frame.into_data() {
            let count = chunk.len() as u64;
            *bytes += count;
            metrics::BYTES_DOWNLOADED_UPSTREAM.increment_by(count);
            if *bytes > content_length.upper().get() {
                let reason = format!(
                    "body exceeded the size limit (received {bytes}, limit {})",
                    content_length.upper()
                );
                return Err(match content_length {
                    ContentLength::Exact(_) => UpstreamError::protocol(reason),
                    ContentLength::Unknown(_) => UpstreamError::body_limit(reason),
                }
                .into());
            }
            writer.write(chunk).await?;
            barrier.ping_batched(count);
        }
    }
    if let ContentLength::Exact(size) = content_length
        && *bytes != size.get()
    {
        return Err(UpstreamError::protocol(format!(
            "body length mismatch (received {bytes}, expected {size})"
        ))
        .into());
    }
    let upstream_done = PreciseInstant::now();
    writer.flush().await?;
    Ok(upstream_done)
}

/// Land the buffered tail after a failed download so a later request can
/// resume from it. [`crate::guards::FailedDownload::salvage`] runs it only when the cache is
/// not what failed.
async fn salvage_partial(writer: &mut DownloadWriter<'_>) {
    if let Err(error) = writer.flush().await {
        error!(
            "Failed to flush partial data after download failure; leaving the partial for resume:  {}",
            ErrorReport(&error)
        );
    }
}

async fn download_file(
    conn_details: &ConnectionDetails,
    warn_on_override: bool,
    (body, content_length): (Incoming, ContentLength),
    (outfile, outpath): (tokio::fs::File, TempPath),
    dbarrier: DownloadBarrier,
    resume_offset: u64,
    request_sent: PreciseInstant,
) {
    let config = global_config();

    let start = PreciseInstant::now();

    debug!(
        "Starting download of file {} from mirror {} for client {}...",
        conn_details.debname, conn_details.mirror, conn_details.client
    );

    let mut bytes = 0;
    let mut writer = DownloadWriter {
        writer: tokio::io::BufWriter::with_capacity(config.buffer_size, outfile),
        path: &outpath,
    };
    let mut body = MaybeRated::new(body, config.min_download_rate, config.rate_check_timeframe);
    let result = dbarrier
        // Detached from the connection that started it: the client either
        // already has its response or joins the registry entry.
        .run(Consequence::Abandon, async |barrier| {
            download_file_worker(&mut body, &mut writer, content_length, &mut bytes, barrier).await
        })
        .await;
    let (dbarrier, t_upstream_done) = match result {
        Ok(done) => done,
        Err(failed) => {
            // run concluded the primary cause; the failed download publishes
            // it once salvaged, or on cancellation of the salvage.
            let _reported = failed
                .salvage(async || salvage_partial(&mut writer).await)
                .await;
            return;
        }
    };
    drop(writer);

    // Not created here: `integrity::rename_into_cache` creates it at commit
    // time, and only on `ENOENT`. The `warn_on_override` `try_exists` below
    // reads a missing directory as "no file to overwrite", which is right.
    let dest_dir_path = conn_details.cache_dir_path();

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
                        "Target file `{}` already exists; overwriting{}",
                        dest_file_path.display(),
                        conn_details.alias_suffix()
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

        // No streamed digest: this path writes through a `BufWriter` whose
        // bytes are not funnelled through a single hashable site, so the
        // commit re-reads and hashes the finished file as before.
        if rbarrier
            .commit(outpath, dest_file_path, total_bytes, None)
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
    let volatile = if conn_details.cached_flavor() == CachedFlavor::Volatile {
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

/// Parse a redirect response's `Location` into a URI.
///
/// The other reasons a redirect is not followed (relative target, unsupported
/// scheme, host not permitted) are named by [`log_unfollowed_redirect`]; a
/// `Location` that does not parse -- or is missing entirely -- would otherwise
/// leave nothing but a bare "failed with code 302" further down. `source` and
/// `what` only name the mirror and resource for the log line.
#[must_use]
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

/// Log why an upstream redirect was not followed, at the point where the
/// follow conditions (absolute `http(s)` target naming a permitted host) have
/// already failed.  Shared by the cache-fetch and the simple-proxy redirect
/// handling so both name the same reason for the same `Location`.
fn log_unfollowed_redirect(moved_uri: &Uri) {
    if moved_uri.scheme().is_none() {
        // A relative Location (`/pool/...`) is legal per RFC 9110, but this
        // backend only follows absolute targets. Reported before the scheme
        // branch below, which would otherwise call it an unsupported scheme.
        debug!("Moved URI `{moved_uri}` is relative; not following the redirect");
    } else if moved_uri.scheme().is_some_and(|scheme| {
        *scheme != http::uri::Scheme::HTTP && *scheme != http::uri::Scheme::HTTPS
    }) {
        debug!("Scheme of moved URI `{moved_uri}` not supported");
    } else if let Some(moved_host) = moved_uri.host() {
        debug!("Host `{moved_host}` of moved URI not permitted");
    } else {
        debug!("Moved URI has no host; not following the redirect");
    }
}

/// Log and build the canonical 503 for a download origination refused by the
/// `max_upstream_downloads` cap (`InsertOutcome::AtCapacity`). The
/// `UPSTREAM_DOWNLOAD_REJECTED_CAP` bump already happened inside
/// `ActiveDownloads::lookup_or_insert`, the enforcement site shared with the
/// splice backend.
#[must_use]
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

/// The registered-download owner retains every terminal setup failure before
/// returning its response. Successful transitions disarm the initial guard.
#[must_use]
async fn serve_new_file(
    conn_details: ConnectionDetails,
    origination: Origination,
    req: Request<Empty<()>>,
    cfstate: CacheFileStat,
    appstate: AppState,
) -> Response<ProxyCacheBody> {
    let status = Arc::clone(&origination.status);
    let barrier = InitBarrier::new(
        origination,
        appstate.active_downloads.clone(),
        &conn_details,
        req.uri().path(),
    );
    match barrier
        .run_settled(async |barrier| {
            serve_new_file_worker(&conn_details, barrier, status, &req, cfstate, &appstate).await
        })
        .await
    {
        Ok(response) => response,
        Err(reported) => {
            // The runner already reported the cause; the status/body pair is
            // the failure's own, and only an upstream cause carries a
            // transport reason cleanup can recover.
            let (status, body) = reported.failure().response_parts();
            let mut response = quick_response(status, body);
            if let DownloadFailure::Upstream(_) = reported.failure() {
                response.extensions_mut().insert(UpstreamFetchError {
                    reason: ErrorReport(reported.failure()).to_string(),
                });
            }
            response
        }
    }
}

/// Runs inline in the connection future (`InitBarrier::run` no longer boxes
/// it), which puts it within roughly 2 KiB of clippy's 16 KiB `large_futures`
/// threshold. Hence the by-reference parameters below: growing this body, or
/// taking a large value by move, will trip the lint at
/// `process_cache_request`. Box the offending inner future -- as
/// `splice/volatile.rs` does for `read_to_vec` -- rather than the runner.
async fn serve_new_file_worker(
    conn_details: &ConnectionDetails,
    ibarrier: &mut InitBarrier,
    status: Arc<tokio::sync::RwLock<ActiveDownloadStatus>>,
    req: &Request<Empty<()>>,
    cfstate: CacheFileStat,
    appstate: &AppState,
) -> Result<(Settled, Response<ProxyCacheBody>), DownloadFailure> {
    // TODO: upstream constant
    const PROXY_CONNECTION: HeaderName = HeaderName::from_static("proxy-connection");

    /// `revalidate` carries the stored upstream validators of a stale
    /// volatile copy; `None` is an unconditional fetch.
    #[must_use]
    fn build_fwd_request(
        uri: &Uri,
        host: &HeaderValue,
        revalidate: Option<&UpstreamMetadata>,
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

        // `Via` names this proxy so a request looping back into it (an
        // `allowed_mirrors` entry covering the proxy's own name) is refused
        // by `preflight_via` instead of served.
        let mut request = Request::builder()
            .method(Method::GET)
            .uri(uri)
            .header(USER_AGENT, APP_USER_AGENT)
            .header(HOST, host)
            .header(VIA, APP_VIA)
            .body(Empty::new())
            .expect("request should be valid");

        if let Some(UpstreamMetadata {
            etag,
            last_modified,
        }) = revalidate
        {
            // The upstream's own `Last-Modified`, never the local mtime:
            // that only dates the last fetch or revalidation, so a copy
            // replayed or lagging behind the upstream would keep drawing
            // 304s. Without a stored date, `If-None-Match` alone asks.
            if let Some((_raw, date)) = last_modified {
                let r = request.headers_mut().append(
                    IF_MODIFIED_SINCE,
                    HeaderValue::try_from(date.format()).expect("HTTP datetime should be valid"),
                );
                assert!(!r, "header does not exist by previous construction");
            }

            let r = request
                .headers_mut()
                .append(CACHE_CONTROL, HeaderValue::from_static("max-age=300"));
            assert!(!r, "header does not exist by previous construction");

            if let Some(etag) = etag.as_deref() {
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

    let (warn_on_override, prev_file_size) = match &cfstate {
        CacheFileStat::Volatile {
            file: _,
            file_path: _,
            prev_size,
        } => (false, *prev_size),
        CacheFileStat::New => (true, 0),
    };

    for (name, value) in req.headers() {
        match name {
            // `Host` is deliberately NOT taken from the client: the ACL and
            // the cache key come from the request-target authority, and a
            // client-chosen `Host` would select another vhost on the same
            // server while the response is cached under the permitted one.
            &USER_AGENT | &RANGE | &IF_RANGE | &ACCEPT | &IF_MODIFIED_SINCE | &CACHE_CONTROL
            | &CONNECTION | &HOST => (),
            n if n == PROXY_CONNECTION => (),

            _ => {
                metrics::UNHANDLED_REQUEST_HEADERS.increment();
                warn_once_or_info!(
                    "Unhandled HTTP header `{name}` with value `{value:?}` in request from client {}; not forwarding it upstream",
                    conn_details.client
                );
            }
        }
    }
    // RFC 3986 §3.2.2: IPv6 addresses must be bracketed in Host headers.
    // The upstream authority, not the canonical mirror: an aliased request
    // dials the host the client named.
    let host = HeaderValue::from_str(&conn_details.upstream_authority())
        .expect("connection host should be valid");
    let host = &host;

    let mut req_uri = Cow::Borrowed(req.uri());

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
        let settled = ibarrier
            .decline(Declined::VerifyThrottled {
                remaining: throttled.remaining,
            })
            .await;
        let head = ResponseHead {
            retry_after: Some(retry_after_secs(throttled.remaining)),
            ..ResponseHead::error(StatusCode::SERVICE_UNAVAILABLE)
        };
        return Ok((
            settled,
            head.into_hyper(full_body("Recently failed checksum verification")),
        ));
    }

    let prefetched_upstream_metadata = match &cfstate {
        CacheFileStat::Volatile {
            file,
            file_path,
            prev_size: _,
        } => {
            let key = conn_details.key();

            Some(cache_metadata::store().resolve(&key, file, file_path))
        }
        CacheFileStat::New => None,
    };
    let revalidate = prefetched_upstream_metadata.as_deref();

    // Permanent files only; see `partial_file::PartialDownload` for the
    // open-once and keep-on-drop rules this relies on.
    let partial_file::PartialResume {
        offset: resume_offset,
        expected_total: resume_expected_total,
        if_range: resume_if_range,
        mut partial,
    } = if conn_details.cached_flavor() == CachedFlavor::Permanent
        && matches!(cfstate, CacheFileStat::New)
    {
        match partial_file::prepare_partial_resume(
            ibarrier,
            &conn_details.debname,
            &conn_details.mirror,
            "",
        )
        .await
        {
            Ok(r) => r,
            Err(partial_file::PartialOpenFailure { failure, guard }) => {
                drop(guard);
                return Err(failure.into());
            }
        }
    } else {
        partial_file::PartialResume::volatile()
    };

    let fwd_request = build_fwd_request(
        &req_uri,
        host,
        revalidate,
        resume_offset,
        resume_if_range.as_deref(),
    );
    trace!("Forwarded request: {fwd_request:?}");

    let mut upstream_request_sent = PreciseInstant::now();
    let mut fwd_response = match request_with_retry(&appstate.https_client, fwd_request).await {
        Ok((r, _parts)) => r,
        Err(error) => {
            return Err(error.into_upstream("request upstream response").into());
        }
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

            req_uri = Cow::Owned(moved_uri);

            let redirected_request = build_fwd_request(
                &req_uri,
                &redirected_host,
                revalidate,
                resume_offset,
                resume_if_range.as_deref(),
            );

            trace!("Forwarded redirected request: {redirected_request:?}");

            upstream_request_sent = PreciseInstant::now();
            let redirected_response =
                match request_with_retry(&appstate.https_client, redirected_request).await {
                    Ok((r, _parts)) => r,
                    Err(error) => {
                        return Err(error.into_upstream("request upstream response").into());
                    }
                };

            trace!("Forwarded redirected response: {redirected_response:?}");

            fwd_response = redirected_response;
        } else {
            log_unfollowed_redirect(&moved_uri);
        }
    }

    // `cfstate` was only needed by reference for the conditional headers of
    // the requests above; a retry below is an unconditional fresh fetch.
    let cached = match cfstate {
        CacheFileStat::Volatile {
            file,
            file_path,
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
        ResumeState::new(
            resume_offset,
            resume_expected_total,
            resume_if_range.as_deref(),
        ),
        conn_details.cached_flavor(),
        cached,
        config.max_object_size,
    ) {
        Ok(plan) => {
            // Answered by the upstream (fresh body or a 304): this is the
            // point the request's Origin row is earned.
            if plan.is_answered() {
                conn_details.record_origin();
            }
            plan
        }
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
                ResumeAnomaly::ETagMismatch => warn_once_or_info!(
                    "Server returned 206 for resume of {} from mirror {} naming an ETag other than the If-Range one; discarding the partial and retrying fresh",
                    conn_details.debname,
                    conn_details.mirror
                ),
            }
            partial.discard_resume().await;

            if anomaly.needs_refetch() {
                // Deliberately no validators here: the partial file has been
                // discarded, so from the upstream's perspective this is a
                // fresh unconditional fetch (no If-Modified-Since, no
                // If-None-Match, no Range).
                let retry_request = build_fwd_request(&req_uri, host, None, 0, None);

                upstream_request_sent = PreciseInstant::now();
                fwd_response = match request_with_retry(&appstate.https_client, retry_request).await
                {
                    Ok((r, _parts)) => r,
                    Err(error) => {
                        return Err(error.into_upstream("request upstream response").into());
                    }
                };
                head = UpstreamHead::from_response(&fwd_response);
            }

            // A resume never revalidates: there is no cached copy to serve.
            plan_fresh_download(
                &head,
                conn_details.cached_flavor(),
                None,
                config.max_object_size,
            )
        }
    };

    let (total_content_length, body_content_length, resume_offset) = match plan {
        DownloadPlan::NotModified((file, file_path)) => {
            note_cached_index_touch(conn_details, req.uri().path(), &file_path);
            if !conn_details.client.is_cleanup_synthetic() {
                metrics::VOLATILE_REFETCHED_UPTODATE.increment();
            }
            let file = touch_volatile_mtime(file, &file_path).await;

            let settled = ibarrier.finished(file_path.clone()).await;

            return Ok((
                settled,
                serve_cached_file(
                    conn_details.clone(),
                    req,
                    file,
                    file_path,
                    prefetched_upstream_metadata.as_deref(),
                    None,
                )
                .await,
            ));
        }
        DownloadPlan::Passthrough => {
            let cleanup_probe = conn_details.client.is_cleanup_synthetic();
            // The relay streams after this function returns, and `decline`
            // gives back the upstream-download slot before that, so the body
            // needs a relay slot of its own. Admitted before `decline`, so
            // joiners learn the 503 a refusal answers rather than the
            // upstream status, and before the log line below, which promises
            // the relay. Cleanup probes relay nothing (answered status-only
            // below).
            let relay_slot = if cleanup_probe {
                None
            } else {
                let Some(slot) = passthrough_limiter::admit(
                    config.max_passthrough_relays,
                    &req_uri,
                    &conn_details.client,
                ) else {
                    return Ok((
                        ibarrier.decline(Declined::RelayRefused).await,
                        quick_response(
                            StatusCode::SERVICE_UNAVAILABLE,
                            passthrough_limiter::REFUSAL_BODY,
                        ),
                    ));
                };
                Some(slot)
            };
            let settled = ibarrier
                .decline(Declined::Passthrough(fwd_response.status()))
                .await;

            // Demote routine 4xx for cleanup-synthetic clients to DEBUG:
            // `try_fetch_packages_file` deliberately walks `.xz → .gz → raw`,
            // and on S3-hosted flat repos every miss surfaces as 403 (not
            // 404). At WARN that's three loud lines per cleanup cycle for
            // a benign probe sequence — the cleanup's own DEBUG line on
            // each miss is the operator-visible record.
            if fwd_response.status() == StatusCode::NOT_FOUND || cleanup_probe {
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
            let Some(relay_slot) = relay_slot else {
                return Ok((settled, quick_response(fwd_response.status(), "")));
            };

            return Ok((
                settled,
                passthrough_response(
                    fwd_response,
                    Subject::Passthrough {
                        host: conn_details.mirror.format_authority().to_string(),
                        path: req_uri.path().to_owned(),
                        client: conn_details.client,
                        request_received_at: conn_details.request_received_at,
                        request_sent: upstream_request_sent,
                        relay_slot,
                    },
                ),
            ));
        }
        DownloadPlan::Reject(reason) => {
            /// One gate per reason: a mirror tripping `max_object_size` must
            /// not mute the first genuine protocol violation.
            static GATES: RejectGates = RejectGates::new();

            reason.record_metrics();
            log_once::warn_once_or_info_gated(
                GATES.for_reason(reason),
                format_args!(
                    "Upstream response rejected for {} from mirror {}: {}; returning 502",
                    conn_details.debname,
                    conn_details.mirror,
                    reason.detail()
                ),
            );
            let settled = ibarrier.decline(Declined::Rejected(reason)).await;
            return Ok((
                settled,
                quick_response(StatusCode::BAD_GATEWAY, reason.body()),
            ));
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

    let reservation = if conn_details.client.is_cleanup_synthetic() {
        // Cleanup's own index fetches are admitted over quota: rejecting
        // them would bail the mirror and the cache could never shrink
        // (`CacheQuota::acquire_for_cleanup`).
        global_cache_quota().acquire_for_cleanup(
            total_content_length,
            prev_file_size,
            &conn_details.debname,
        )
    } else {
        match global_cache_quota().try_acquire(
            total_content_length,
            prev_file_size,
            &conn_details.debname,
        ) {
            Ok(r) => r,
            Err(QuotaExceeded) => {
                return Ok((
                    ibarrier.decline(Declined::QuotaExceeded).await,
                    quick_response(StatusCode::SERVICE_UNAVAILABLE, "Disk quota reached"),
                ));
            }
        }
    };

    // Wording mirrors `splice/http.rs::UpstreamResponse::discard_invalid_validators`
    // modulo the subsystem prefix. The raw values are read the way splice's
    // `find_header` reads them, as UTF-8 rather than through `to_str` (visible
    // ASCII only): an obs-text value then reaches the check and its warn
    // instead of vanishing silently, so both backends log it alike.
    let (upstream_etag, upstream_last_modified) = check_upstream_validators(
        fwd_response
            .headers()
            .get(ETAG)
            .and_then(|hv| std::str::from_utf8(hv.as_bytes()).ok())
            .map(String::from),
        fwd_response
            .headers()
            .get(LAST_MODIFIED)
            .and_then(|hv| std::str::from_utf8(hv.as_bytes()).ok())
            .map(String::from),
        |invalid| match invalid {
            InvalidValidator::ETag(etag) => warn_once_or_info!(
                "Upstream mirror {} sent an invalid ETag `{}` for {}; discarding it",
                conn_details.mirror,
                etag.escape_debug(),
                conn_details.debname
            ),
            InvalidValidator::LastModified(lm) => warn_once_or_info!(
                "Upstream mirror {} sent an invalid Last-Modified `{}` for {}; discarding it",
                conn_details.mirror,
                lm.escape_debug(),
                conn_details.debname
            ),
            InvalidValidator::Oversized { header, len } => warn_once_or_info!(
                "Upstream mirror {} sent a {len} byte {header} for {}; discarding it",
                conn_details.mirror,
                conn_details.debname
            ),
        },
    );

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

    // A resumed `206` keeps the partial's validators it does not repeat
    // (`inherit_resumed`); read them before `into_target` consumes the partial.
    let upstream_metadata = Arc::new(
        UpstreamMetadata::from_upstream(upstream_etag, upstream_last_modified)
            .inherit_resumed(partial.resumed_validators()),
    );
    let target_file = partial.target_file();

    // Create/open the output file: partial path for permanent files, random temp for volatile.
    // Defuse the guard once we take ownership of the partial path — from here on, the
    // download's own `OnDrop::Keep` TempPath manages the file lifetime.
    let (outfile, outpath) = partial.into_target(filename, resume_offset).await?;
    // Persist the validators (and the expected total, so a resume can detect
    // an upstream change) early, so they survive an interrupted download.
    let expected_size = match total_content_length {
        ContentLength::Exact(total) => Some(total.get()),
        ContentLength::Unknown(_) => None,
    };
    write_upstream_metadata(
        &outfile,
        &outpath,
        &upstream_metadata,
        expected_size,
        target_file,
    );

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

    let (settled, dbarrier) = ibarrier
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

    // The parallel-download hack: hand the client a `Retry-After` nudge and
    // let the spawned `download_file` above finish on its own; the retry
    // late-joins it. `splice/mod.rs` gates on the same three functions.
    if should_nudge(
        config,
        conn_details.cached_flavor(),
        || appstate.active_downloads.upstream_slots(),
        total_content_length.upper(),
        &mut rand::rng(),
    ) {
        log_nudge(conn_details, config, "");
        let response = nudge_head(config).into_hyper(full_body(NUDGE_BODY));
        trace!("Outgoing parallel download hack response: {response:?}");
        return Ok((settled, response));
    }

    Ok((
        settled,
        serve_downloading_file(conn_details.clone(), req, status, Some(&upstream_metadata)).await,
    ))
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
    let upgraded = TokioIo::new(upgraded);

    /* Proxying data */
    // not rate-checked; idle-bounded by `client_idle_timeout`
    let outcome = copy_bidirectional_idle(
        upgraded,
        &mut server,
        config.buffer_size,
        config.client_idle_timeout,
    )
    .await;
    report_tunnel_outcome(&outcome, &client, host, port, start.elapsed());

    Ok(())
}

/// Cache lookup plus hit/miss accounting for a request hyper classified
/// itself (or cleanup's synthetic index fetches), then serve or fetch.
///
/// This is the lookup site: `CACHE_HITS` / `CACHE_MISSES` /
/// `VOLATILE_REFETCHED` (and `VOLATILE_HIT` in [`serve_volatile_file`]) are
/// bumped exactly where the lookup decides.  Requests the sendfile backend
/// already looked up never come here - their `HandoffPlan::CacheMiss`
/// enters [`serve_cache_miss`] directly, so no bump can repeat.
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
            // in VOLATILE_HIT / VOLATILE_REFETCHED.
            if conn_details.cached_flavor() == CachedFlavor::Permanent {
                metrics::CACHE_HITS.increment();
            }
            conn_details.refresh_origin();

            trace!(
                "File {} found, serving {} version...",
                cache_path.display(),
                match conn_details.cached_flavor() {
                    CachedFlavor::Permanent => "permanent",
                    CachedFlavor::Volatile => "volatile",
                }
            );
            match conn_details.cached_flavor() {
                CachedFlavor::Volatile => {
                    serve_volatile_file(conn_details, req, file, cache_path, appstate).await
                }
                CachedFlavor::Permanent => {
                    note_cached_index_touch(&conn_details, req.uri().path(), &cache_path);
                    serve_cached_file(conn_details, &req, file, cache_path, None, None).await
                }
            }
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            match conn_details.cached_flavor() {
                CachedFlavor::Permanent => metrics::CACHE_MISSES.increment(),
                CachedFlavor::Volatile => {
                    // Cleanup-synthetic probes are operator bookkeeping, not
                    // user traffic - exclude them so the dashboard ratio
                    // reflects real client behavior only.
                    if !conn_details.client.is_cleanup_synthetic() {
                        metrics::VOLATILE_REFETCHED.increment();
                    }
                }
            }

            serve_cache_miss(conn_details, req, cache_path, CacheMiss::NotFound, appstate).await
        }
        Err(err) => {
            metrics::CACHE_IO_FAILURE.increment();
            error!(
                "Failed to open file `{}`; returning 500:  {}",
                cache_path.display(),
                ErrorReport(&err)
            );
            cache_access_failure()
        }
    }
}

/// Keeps [`handle_hyper_connection`] -- and with it the connection's
/// admission slot (`client_counter::ClientCounter`, owned by the task that
/// runs the handler) -- alive while a tunnel upgraded from the connection
/// runs.
///
/// hyper finishes serving a connection as soon as it has handed the upgraded
/// socket to the tunnel task, so without this the slot was released while
/// the tunnel still held the client socket, and every hyper tunnel escaped
/// `max_connections` and `max_connections_per_client_ip`. Each tunnel task
/// holds a clone; the handler waits until every clone is gone.
#[derive(Clone)]
struct ConnectionHold {
    /// Never sends: the receiver only waits for every clone to drop.
    _sender: tokio::sync::mpsc::Sender<Never>,
}

/// Answer a `CONNECT` whose client already passed the proxy-client ACL in
/// `preflight_method`.
#[must_use]
fn connect_response(
    client: ClientInfo,
    req: Request<Incoming>,
    hold: ConnectionHold,
) -> Response<ProxyCacheBody> {
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
        let _hold = hold;
        match hyper::upgrade::on(req).await {
            Ok(upgraded) => {
                // The relay outcome is reported inside `tunnel`; only the
                // upstream connect can still fail here.
                if let Err(err) = tunnel(client, upgraded, &host, port).await {
                    metrics::TUNNEL_TRANSFER_FAILED.increment();
                    if err.kind() == std::io::ErrorKind::TimedOut {
                        info!(
                            "Tunnel for client {client} to {host}:{port} timed out:  {}",
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

    let response = ResponseHead::tunnel_established().into_hyper(empty_body());

    trace!("Outgoing response: {response:?}");

    response
}

/// Work the sendfile backend already did for the first request hyper parses
/// on a handed-off connection (`sendfile_conn::handle_sendfile_connection`).
///
/// Sendfile parses the request, runs the shared pre-flight,
/// `authorize_cache_access` and `dispatch_request`, and - for a `Cache`
/// outcome - the cache lookup or late-joiner attach, before deciding it
/// cannot answer the request itself.  The plan carries those results so
/// [`pre_process_client_request`] enters the pipeline exactly where sendfile
/// left it: pre-flight and dispatch run once per request, the deferred
/// `Origin` write and `record_uncacheable` fire once, and every
/// hit/miss/refetch bump belongs to the one lookup that ran.
///
/// Pairing invariant: the bytes prepended to hyper's stream are exactly the
/// request sendfile parsed (plus any pipelined successors it has not looked
/// at), and hyper invokes the service once per parsed request in stream
/// order, so the plan pairs with the *first* service invocation and only
/// that one - see [`handle_hyper_connection`].
///
/// With `splice` the sendfile backend fetches misses and forwards
/// passthroughs itself, so only [`Self::JoinDownload`] exists there.
#[cfg_attr(
    not(feature = "sendfile"),
    expect(dead_code, reason = "constructed only by the sendfile backend")
)]
#[derive(Debug)]
pub(crate) enum HandoffPlan {
    /// Dispatch routed through the cache pipeline and sendfile's lookup found
    /// nothing it could serve.  Hit/miss accounting is done; hyper only
    /// fetches (or joins the in-flight fetch).
    #[cfg(not(feature = "splice"))]
    CacheMiss {
        conn_details: ConnectionDetails,
        cache_path: PathBuf,
        miss: CacheMiss,
    },
    /// Dispatch routed through the cache pipeline and sendfile attached to a
    /// download already in flight, but cannot frame the response itself
    /// (upstream sent no `Content-Length`).  Late-joiner and miss accounting
    /// are done; hyper streams the in-flight download.
    JoinDownload {
        conn_details: ConnectionDetails,
        status: Arc<tokio::sync::RwLock<ActiveDownloadStatus>>,
    },
    /// Dispatch declined to cache; `record_uncacheable` already ran inside
    /// the dispatcher.  Hyper forwards the request uncached.
    #[cfg(not(feature = "splice"))]
    Passthrough {
        reason: PassthroughReason,
        requested_host: ClientHost,
        requested_port: Option<NonZero<u16>>,
        request_received_at: PreciseInstant,
    },
}

#[inline]
async fn pre_process_client_request_wrapper(
    client: ClientInfo,
    req: Request<Incoming>,
    appstate: AppState,
    handoff: Option<HandoffPlan>,
    hold: ConnectionHold,
) -> Result<Response<ProxyCacheBody>, Infallible> {
    let response = pre_process_client_request(client, req, appstate, handoff, hold).await;
    metrics::record_client_status(response.status());
    Ok(response)
}

/// The response to a shared pre-flight rejection: an authorization refusal
/// also ends the connection (`RejectReason::is_authorization_refusal`), as
/// in the sendfile backend.
#[must_use]
fn reject_response(reason: RejectReason) -> Response<ProxyCacheBody> {
    let (status, msg) = reason.response_parts();
    if reason.is_authorization_refusal() {
        quick_response_closing(status, msg)
    } else {
        quick_response(status, msg)
    }
}

/// Drop the request body (never forwarded) so the rest of the pipeline
/// handles a bodiless `Request<Empty<()>>`.
#[must_use]
fn strip_request_body(client: ClientInfo, req: Request<Incoming>) -> Request<Empty<()>> {
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
    Request::from_parts(parts, Empty::new())
}

/// A request the cache pipeline declined, on its way to the simple proxy.
/// Carries what the forwarding tail needs, whichever verdict produced it:
/// the sendfile backend's `HandoffPlan::Passthrough` or this backend's own
/// [`dispatch_request`].
struct PassthroughRequest {
    reason: PassthroughReason,
    requested_host: ClientHost,
    requested_port: Option<NonZero<u16>>,
    request_received_at: PreciseInstant,
}

/// Entry point for every request hyper serves.  With a [`HandoffPlan`] the
/// request was already pre-flighted and dispatched by the sendfile backend
/// (which also bumped `REQUESTS_TOTAL` for it); without one this is the
/// proxy entry and everything runs here.
#[must_use]
async fn pre_process_client_request(
    client: ClientInfo,
    req: Request<Incoming>,
    appstate: AppState,
    handoff: Option<HandoffPlan>,
    hold: ConnectionHold,
) -> Response<ProxyCacheBody> {
    trace!("Incoming request: {req:?}");

    let handoff_passthrough: Option<PassthroughRequest> = match handoff {
        #[cfg(not(feature = "splice"))]
        Some(HandoffPlan::CacheMiss {
            conn_details,
            cache_path,
            miss,
        }) => {
            let req = strip_request_body(client, req);
            return serve_cache_miss(conn_details, req, cache_path, miss, appstate).await;
        }
        Some(HandoffPlan::JoinDownload {
            conn_details,
            status,
        }) => {
            let req = strip_request_body(client, req);
            debug!(
                "Serving file {} already in download from mirror {} for client {}...",
                conn_details.debname, conn_details.mirror, conn_details.client
            );
            return serve_downloading_file(conn_details, &req, status, None).await;
        }
        #[cfg(not(feature = "splice"))]
        Some(HandoffPlan::Passthrough {
            reason,
            requested_host,
            requested_port,
            request_received_at,
        }) => Some(PassthroughRequest {
            reason,
            requested_host,
            requested_port,
            request_received_at,
        }),
        None => None,
    };

    let (req, passthrough) = if let Some(passthrough) = handoff_passthrough {
        (strip_request_body(client, req), passthrough)
    } else {
        metrics::REQUESTS_TOTAL.increment();

        let acls = ClientAcls::new(global_config(), global_webif_hosts());

        match preflight_method(req.method().as_str(), &client, &acls) {
            Ok(RequestKind::Connect) => return connect_response(client, req, hold),
            Ok(RequestKind::Get) => {}
            Err(reason) => return reject_response(reason),
        }

        let via_values = req
            .headers()
            .get_all(VIA)
            .iter()
            .filter_map(|v| v.to_str().ok());
        if let Err(reason) = preflight_via(via_values, &client) {
            let (status, msg) = reason.response_parts();
            return quick_response(status, msg);
        }

        let (requested_host, requested_port) = match preflight_target(
            req.uri(),
            req.version() == http::Version::HTTP_11,
            || req.headers().get(HOST).map(HeaderValue::as_bytes),
            &client,
            &acls,
        ) {
            Ok(RequestTarget::Proxy { host, port }) => (host, port),
            Ok(RequestTarget::WebUi) => {
                return serve_web_interface(req.uri(), &appstate)
                    .await
                    .into_hyper_response();
            }
            Err(reason) => return reject_response(reason),
        };

        // Closing, like the sendfile backend: a refused proxy client must
        // not keep its connection slot by asking again.
        let requested_host = match authorize_cache_access(&client, requested_host) {
            Ok(rh) => rh,
            Err((status, msg)) => return quick_response_closing(status, msg),
        };

        let req = strip_request_body(client, req);

        let path_and_query = req
            .uri()
            .path_and_query()
            .map_or_else(|| req.uri().path(), PathAndQuery::as_str);
        match dispatch_request(path_and_query, requested_host, requested_port, &client).await {
            DispatchOutcome::Cache(conn_details) => {
                return process_cache_request(conn_details, req, appstate).await;
            }
            DispatchOutcome::Reject(reason) => {
                let (status, msg) = reason.response_parts();
                return quick_response(status, msg);
            }
            DispatchOutcome::Passthrough {
                reason,
                requested_host,
                request_received_at,
            } => (
                req,
                PassthroughRequest {
                    reason,
                    requested_host,
                    requested_port,
                    request_received_at,
                },
            ),
        }
    };

    let PassthroughRequest {
        reason: passthrough_reason,
        requested_host,
        requested_port,
        request_received_at: passthrough_request_received_at,
    } = passthrough;

    assert_eq!(req.method(), Method::GET, "Filtered at function start");

    //
    // Simple proxy (without any caching)
    //

    let Some(relay_slot) =
        passthrough_limiter::admit(global_config().max_passthrough_relays, req.uri(), &client)
    else {
        return quick_response(
            StatusCode::SERVICE_UNAVAILABLE,
            passthrough_limiter::REFUSAL_BODY,
        );
    };

    warn_once_or_info!(
        "Proxying (without caching) request {} for client {client} ({})",
        req.uri(),
        passthrough_reason.label()
    );

    // Built from scratch like the cache fetch (and the splice passthrough):
    // no client header is forwarded. Client credentials
    // (`Proxy-Authorization`), hop-by-hop fields and a `Content-Length` for
    // the body `strip_request_body` dropped must never reach the shared
    // upstream pool. The upstream `Host` is the request-target authority,
    // never the client's own header; `Via` closes proxy loops as in
    // `build_fwd_request`. The redirect follow below reuses these headers.
    let (parts, _body) = req.into_parts();
    let mut fwd_request = Request::builder()
        .method(Method::GET)
        .header(USER_AGENT, APP_USER_AGENT)
        .header(VIA, APP_VIA);
    if let Some(authority) = parts.uri.authority() {
        fwd_request = fwd_request.header(HOST, host_header_from_uri(authority));
    }
    let fwd_request = fwd_request
        .uri(parts.uri)
        .body(Empty::new())
        .expect("request should be valid");

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

    // Only a 2xx proves the index exists; `from_path` mints nothing the
    // cache itself would refuse.
    if fwd_response.status().is_success()
        && let Some(origin) = Origin::from_path(
            parts.uri.path(),
            requested_host.clone(),
            requested_port,
            &client,
        )
    {
        debug!("Extracted origin: {origin:?}");

        // TODO: cache some of them?
        let cmd = DatabaseCommand::Origin(origin, OriginSighting::Upstream);
        send_db_command(cmd).await;
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

            return passthrough_response(
                redirected_response,
                Subject::Passthrough {
                    host: requested_host.to_string(),
                    path: request_path,
                    client,
                    request_received_at: passthrough_request_received_at,
                    request_sent: redirected_request_sent,
                    relay_slot,
                },
            );
        }

        log_unfollowed_redirect(&moved_uri);
    }

    passthrough_response(
        fwd_response,
        Subject::Passthrough {
            host: requested_host.to_string(),
            path: request_path,
            client,
            request_received_at: passthrough_request_received_at,
            request_sent: fwd_request_sent,
            relay_slot,
        },
    )
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

/// The body failure hyper erased into `err`'s source chain, if any. Hyper
/// boxes the body's error type as-is, so the chain holds a [`DeliveryFailure`]
/// by concrete type exactly when [`ProxyCacheBody`]'s error type *is*
/// `DeliveryFailure` -- a wrapper there (a `Box`, a newtype) would hide it from
/// this downcast. The owning `AccountedBody` already reported it; socket-only
/// failures carry none and stay connection-level.
fn accounted_body_failure<'a>(
    err: &'a (dyn std::error::Error + 'static),
) -> Option<&'a DeliveryFailure> {
    let mut cause = err.source();
    while let Some(error) = cause {
        if let Some(failure) = error.downcast_ref::<DeliveryFailure>() {
            return Some(failure);
        }
        cause = error.source();
    }
    None
}

/// The request-head allowance in [`client_max_buf_size`], and its floor:
/// the sendfile backend refuses a head past 8 KiB, and twice that leaves
/// room for a pipelined request behind a maximal head in a sendfile handoff.
const CLIENT_HEAD_ALLOWANCE: usize = 16 * 1024;

/// `max_buf_size` of the client-facing server connection, i.e. hyper
/// serving an apt client. Not the upstream hyper client's read buffer,
/// which `main.rs` caps separately (`limits::MAX_UPSTREAM_READ_BUFFER`).
///
/// It bounds two buffers, because hyper has one setting for both:
/// - the read buffer, and so the request head hyper accepts (a longer one is
///   answered 431). hyper's default is ~400 KiB, held per connection for up
///   to `client_idle_timeout`.
/// - the write queue (`WriteBuf::can_buffer`): once the queued bytes reach
///   the limit, hyper flushes before it polls the body for the next frame.
///   Below one body frame (`buffer_size`) that serialises every file read
///   behind the previous frame's socket write: at 16 KiB with 32 KiB frames
///   a loopback cache hit through the stream body measured about 24 % less
///   throughput and 14 % more CPU per MiB than with no limit.
///
/// Hence `buffer_size` plus [`CLIENT_HEAD_ALLOWANCE`], never below that
/// allowance: one queued frame (plus its response head) stays under the
/// limit, so the next file read overlaps the write, while the head bound
/// (48 KiB at the default 32 KiB `buffer_size`) stays far below hyper's
/// default.
#[must_use]
fn client_max_buf_size(buffer_size: usize) -> usize {
    CLIENT_HEAD_ALLOWANCE.max(buffer_size.saturating_add(CLIENT_HEAD_ALLOWANCE))
}

/// Serve every request on `stream` through hyper.
///
/// `handoff` is `Some` when the sendfile backend hands over a connection
/// whose first request it already parsed and dispatched: the plan applies to
/// the first request hyper's service sees and to nothing after it (later
/// keep-alive requests on the connection run the full pipeline here).
pub(crate) async fn handle_hyper_connection<T>(
    stream: T,
    client: ClientInfo,
    appstate: AppState,
    handoff: Option<HandoffPlan>,
) where
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

    // The plan pairs with the first service invocation only: the stream's
    // prepended bytes are exactly the request sendfile parsed (with any
    // pipelined successors behind it), hyper invokes the service once per
    // parsed request in stream order, and a request hyper cannot parse ends
    // the connection with hyper's own 400 rather than skipping to the next
    // one - so the first invocation is that request, and `take()` makes
    // every later invocation run the full pipeline.
    let handoff = parking_lot::Mutex::new(handoff);

    // Lent to every tunnel this connection upgrades into; see
    // `ConnectionHold`. The service owns the sender, so it is dropped with
    // the connection future below.
    let (sender, mut tunnels_done) = tokio::sync::mpsc::channel::<Never>(1);
    let hold = ConnectionHold { _sender: sender };

    let served = http1::Builder::new()
        .timer(hyper_util::rt::TokioTimer::new())
        .header_read_timeout(global_config().client_idle_timeout)
        .max_buf_size(client_max_buf_size(global_config().buffer_size))
        .serve_connection(
            TokioIo::new(stream),
            service_fn(move |req| {
                pre_process_client_request_wrapper(
                    client,
                    req,
                    appstate.clone(),
                    handoff.lock().take(),
                    hold.clone(),
                )
            }),
        )
        .with_upgrades()
        .await;

    if let Err(err) = served {
        if let Some(failure) = accounted_body_failure(&err) {
            debug!(
                "Closing connection to client {client} after accounted body failure:  {}",
                ErrorReport(failure)
            );
        } else if err.is_incomplete_message() || hyper_is_peer_disconnect(&err) {
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
        } else {
            error!(
                "Failed to serve connection for client {client}; closing the connection:  {}",
                ErrorReport(&err)
            );
        }
    }

    // Return (and so release the connection's slot) only once every tunnel
    // upgraded from this connection has ended.
    match tunnels_done.recv().await {
        None => {}
        Some(never) => match never {},
    }
}

#[cfg(test)]
mod tests {
    use super::{SchemeDecision, UpgradeProbe, Uri, host_header_from_uri};

    /// Hyper erases a body error through `Into<Box<dyn Error + Send + Sync>>`
    /// and exposes the box as its own `source()`. The connection handler must
    /// find the body's typed failure there, or every accounted body failure
    /// also reaches its generic `error!` arm.
    #[test]
    fn accounted_body_failure_survives_hyper_erasure() {
        use std::error::Error;

        use super::{Body, ProxyCacheBody, accounted_body_failure};
        use crate::transfer_error::{ClientError, DeliveryFailure};

        /// Stands in for `hyper::Error`: the erased body error is its source.
        #[derive(Debug, thiserror::Error)]
        #[error("error from user's Body stream")]
        struct Erased(#[source] Box<dyn Error + Send + Sync>);

        fn erase(error: <ProxyCacheBody as Body>::Error) -> Box<dyn Error + Send + Sync> {
            error.into()
        }

        let failure: DeliveryFailure =
            ClientError::io("write client", std::io::ErrorKind::BrokenPipe.into()).into();
        let erased = Erased(erase(failure));
        let found = accounted_body_failure(&erased).expect("typed body failure in the chain");
        assert!(found.is_peer_disconnect());

        let socket = Erased(Box::new(std::io::Error::from(
            std::io::ErrorKind::ConnectionReset,
        )));
        assert!(accounted_body_failure(&socket).is_none());
    }

    /// One `buffer_size` frame must stay below the limit, or hyper flushes
    /// it before polling the body for the next (see `client_max_buf_size`).
    #[test]
    fn client_max_buf_size_leaves_room_for_one_frame_and_a_head() {
        use super::{CLIENT_HEAD_ALLOWANCE, client_max_buf_size};
        assert_eq!(client_max_buf_size(32 * 1024), 48 * 1024);
        for buffer_size in [1024, 32 * 1024, 128 * 1024, 16 * 1024 * 1024] {
            let limit = client_max_buf_size(buffer_size);
            assert!(limit >= CLIENT_HEAD_ALLOWANCE);
            assert!(limit >= buffer_size + CLIENT_HEAD_ALLOWANCE);
        }
        assert_eq!(client_max_buf_size(usize::MAX), usize::MAX);
    }

    #[tokio::test]
    async fn cached_file_truncation_is_a_cache_failure() {
        use super::{Body as _, CachedFileBody, metrics};
        use std::pin::Pin;
        let before = metrics::CACHE_IO_FAILURE.get();
        let file = tempfile::tempfile().unwrap();
        let mut body = CachedFileBody::new(
            tokio::fs::File::from_std(file),
            4,
            4096,
            "truncated-cache-file".into(),
        );
        let error = std::future::poll_fn(|cx| Pin::new(&mut body).poll_frame(cx))
            .await
            .unwrap()
            .unwrap_err();
        assert!(error.to_string().contains("file shorter than promised"));
        assert_eq!(
            metrics::CACHE_IO_FAILURE.get(),
            before,
            "a short file is a consistency anomaly, not a failed syscall"
        );
        assert!(body.is_end_stream());
        assert!(
            std::future::poll_fn(|cx| Pin::new(&mut body).poll_frame(cx))
                .await
                .is_none()
        );
    }

    /// Only an uncached `Auto` decision may fall back to the original
    /// scheme; `Always` probes without a fallback, and a fixed scheme is no
    /// probe at all. The metrics identity
    /// `ATTEMPTED == SUCCEEDED + REVERTED + FAILED` rests on this mapping.
    #[test]
    fn upgrade_probe_of_decision() {
        assert_eq!(
            UpgradeProbe::of(SchemeDecision::Http),
            UpgradeProbe::NotProbing
        );
        assert_eq!(
            UpgradeProbe::of(SchemeDecision::Https),
            UpgradeProbe::NotProbing
        );
        assert_eq!(
            UpgradeProbe::of(SchemeDecision::AutoUpgrade),
            UpgradeProbe::Revertible
        );
        assert_eq!(
            UpgradeProbe::of(SchemeDecision::AlwaysUpgrade),
            UpgradeProbe::Committed
        );

        assert!(!UpgradeProbe::NotProbing.is_probing());
        assert!(UpgradeProbe::Revertible.is_probing());
        assert!(UpgradeProbe::Committed.is_probing());
    }

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
