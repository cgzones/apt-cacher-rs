//! Acquiring an upstream exchange for a cache-miss download:
//! [`standard_upstream_connect`] owns the retry/backoff envelope over pool
//! checkout + connect + send + read-headers, [`follow_redirect`] and
//! [`discard_partial_and_retry`] replace the exchange on a redirect or a
//! non-resumable partial, and [`acquire_upstream`] wraps the kTLS fast path
//! around all of it. The result is an [`UpstreamExchange`] (connection,
//! parsed head, header buffer and body-prefix boundary) or one of the
//! [`UpstreamAcquire`] short-circuits.
//!
//! Consumers: the drive in `mod.rs` (`acquire_upstream`, the reconnect
//! helpers, `warn_upstream_reject`), `simple_proxy` and `cleanup_bridge`
//! (`standard_upstream_connect`).

use std::num::NonZero;
#[cfg(feature = "ktls")]
use std::path::PathBuf;

use bytes::BytesMut;
use http::StatusCode;
use tracing::debug;

use crate::cache_layout::ConnectionDetails;
use crate::config::ClientHost;
use crate::deb_mirror::{Mirror, MirrorKind};
use crate::error::ErrorReport;
use crate::humanfmt::HumanFmt;
use crate::scheme_cache::SchemeDecision;
use crate::upstream_head::RejectReason;
#[cfg(feature = "ktls")]
use crate::upstream_head::{DownloadPlan, plan_fresh_download};
use crate::utils;
use crate::{
    Scheme, global_config, metrics, permitted_host_cache::is_host_allowed_cached, scheme_cache,
    upstream_retry, warn_once_or_info, warn_once_or_info_logged,
};

use super::http::{UpstreamResponse, send_and_read_headers};
#[cfg(feature = "ktls")]
use super::ktls_path::{KtlsReadyState, KtlsResult, try_unbuffered_ktls_connect};
#[cfg(feature = "ktls")]
use super::upstream::UpstreamConn;
use super::upstream::{
    ConnLabel, ConnectRetry, PoolGuard, connect_upstream, mirror_port, pool_checkout,
};
use super::{SpliceProxyError, UpstreamFailure, VolatileCondHeaders};

/// One upstream request/response in flight: the pool-guarded connection the
/// response arrived on, its parsed head, and the bytes read alongside it
/// (`header_buf[header_end..]` is the body prefix). Built only by
/// [`standard_upstream_connect`] and the kTLS `Ready` arm of
/// [`acquire_upstream`], and replaced wholesale by the reconnect helpers
/// ([`follow_redirect`], [`discard_partial_and_retry`]), so every field always
/// describes the same connection.
pub(super) struct UpstreamExchange {
    pub(super) conn: PoolGuard,
    pub(super) response: UpstreamResponse,
    pub(super) header_buf: BytesMut,
    pub(super) header_end: usize,
    /// Whether `conn` came out of the pool rather than a fresh connect.
    pub(super) reused: bool,
}

impl UpstreamExchange {
    /// Log suffix naming this exchange's connection flavour.
    #[must_use]
    pub(super) fn label(&self) -> ConnLabel {
        let Self {
            conn,
            response: _,
            header_buf: _,
            header_end: _,
            reused,
        } = self;
        ConnLabel {
            mode: conn.tls_mode(),
            reused: *reused,
        }
    }
}

/// Outcome of [`acquire_upstream`].
#[cfg_attr(
    feature = "ktls",
    expect(
        clippy::large_enum_variant,
        reason = "Exchange is the overwhelmingly common variant; boxing it would cost an allocation per download"
    )
)]
pub(super) enum UpstreamAcquire {
    /// Response head in hand on a live connection.
    Exchange(UpstreamExchange),
    /// The kTLS attempt's 200 has no usable Content-Length and the planner
    /// refused it (already logged and counted, upstream status recorded). No
    /// connection is left: the caller answers 502 with `reason.body()`.
    #[cfg(feature = "ktls")]
    KtlsReject(RejectReason),
    /// The kTLS attempt got a 304 for a volatile file whose cached copy lives
    /// at this path (upstream status recorded). No connection is left: the
    /// caller serves the cached file.
    #[cfg(feature = "ktls")]
    KtlsNotModified(PathBuf),
}

/// Update the scheme cache for a mirror after successful connection.
fn cache_scheme(mirror: &Mirror, scheme: Scheme) {
    if scheme_cache::record_success(mirror.into(), scheme) {
        debug!(
            "splice proxy: cached {scheme} scheme for {}",
            mirror.format_authority()
        );
    }
}

/// Standard (non-kTLS) upstream connect→request→read-headers→parse pipeline.
/// Tries a pooled connection first; falls back to a fresh connection on failure.
///
/// Times out after the configured HTTP timeout.
pub(super) async fn standard_upstream_connect(
    mirror: &Mirror,
    host_authority: &str,
    upstream_path: &str,
    resume_offset: u64,
    resume_if_range: Option<&str>,
    volatile_cond: Option<&VolatileCondHeaders>,
    scheme_override: Option<Scheme>,
) -> Result<UpstreamExchange, UpstreamFailure> {
    // Resolve the scheme decision ONCE per connect: it drives the pool-lookup
    // key, the HTTPS-upgrade accounting, and the connect itself. A per-request
    // redirect forcing the scheme carries no decision, and so does none of the
    // scheme-cache / upgrade-metric bookkeeping below.
    let (resolved_scheme, decision) = if let Some(scheme) = scheme_override {
        (Some(scheme), None)
    } else {
        let decision = scheme_cache::resolve(mirror.into(), global_config());
        // `None` = Auto upgrade, i.e. try HTTPS then fall back to HTTP.
        (decision.fixed_scheme(), Some(decision))
    };

    // Try a pooled connection first. In Auto mode without a cached scheme there
    // is no key to look up by, so account for it as `POOL_MISS_NO_SCHEME` and
    // fall through to the fresh-connect path — the invariant
    // `POOL_NEW ≈ sum(POOL_MISS_*)` then holds for first connections too.
    if let Some(scheme) = resolved_scheme {
        let is_tls = matches!(scheme, Scheme::Https);
        let port = mirror_port(mirror, is_tls);
        if let Some(mut pooled) = pool_checkout(mirror.host(), port, is_tls) {
            if pooled.check_alive(mirror.host(), port) {
                match send_and_read_headers(
                    &mut pooled,
                    host_authority,
                    upstream_path,
                    resume_offset,
                    resume_if_range,
                    volatile_cond,
                )
                .await
                {
                    Ok((resp, hdr_buf, hdr_end)) => {
                        let poolable = !resp.connection_close;
                        metrics::POOL_REUSED.increment();
                        return Ok(UpstreamExchange {
                            conn: PoolGuard::new(pooled, mirror.host().to_string(), port, poolable),
                            response: resp,
                            header_buf: hdr_buf,
                            header_end: hdr_end,
                            reused: true,
                        });
                    }
                    Err(err) => {
                        metrics::POOL_MISS_FAILED.increment();
                        debug!(
                            "splice proxy: pooled connection to {host_authority} failed, \
                             opening fresh:  {}",
                            ErrorReport(&err)
                        );
                    }
                }
            } else {
                metrics::POOL_MISS_DEAD.increment();
                debug!("splice proxy: pooled connection to {host_authority} is dead, discarding");
            }
        } else {
            metrics::POOL_MISS_EMPTY.increment();
        }
    } else {
        metrics::POOL_MISS_NO_SCHEME.increment();
    }

    debug!("splice proxy: no pooled connection to {host_authority}, opening fresh...");

    metrics::POOL_NEW.increment();

    // HTTPS-upgrade accounting, read off the decision resolved above. The timing
    // and the deliberate divergences from hyper are documented on the counters in
    // metrics.rs.
    if decision.is_some_and(SchemeDecision::is_upgrade_attempt) {
        metrics::HTTPS_UPGRADE_ATTEMPTED.increment();
    }

    let mut backoff = upstream_retry::Backoff::new(
        global_config().upstream_retry_budget,
        coarsetime::Instant::now(),
    );
    let (mut up, scheme) = loop {
        let err = match connect_upstream(mirror, resolved_scheme).await {
            Ok(conn) => break conn,
            Err(err) => err,
        };
        let attempt = backoff.attempt();
        // A permanent failure repeats identically on every retry, so it skips
        // the budget and drops straight into the terminal branch below --
        // sparing 10 pointless TCP connects and TLS handshakes.
        let permanent = err.retry == ConnectRetry::Permanent;
        let next = if permanent {
            None
        } else {
            backoff.next_retry(coarsetime::Instant::now())
        };
        let Some(delay) = next else {
            let logged = if permanent {
                warn_once_or_info_logged!(
                    "splice proxy: not retrying permanent connect failure to upstream {host_authority} for {upstream_path}; returning 502:  {}",
                    ErrorReport(&err.err)
                )
            } else {
                // The limit names which budget stopped the retries -- attempt
                // cap or `upstream_retry_budget`.
                warn_once_or_info_logged!(
                    "splice proxy: failed to connect to upstream {host_authority} for {upstream_path} after {attempt} connection attempts ({}); returning 502:  {}",
                    backoff.limit(),
                    ErrorReport(&err.err)
                )
            };
            if let Some(decision) = decision {
                // Evict a stale cached scheme so the next request re-resolves,
                // mirroring the hyper backend.
                if let Some(scheme) = scheme_cache::record_failure(mirror.into()) {
                    // A learned scheme is sticky, so losing it silently changes
                    // how every later request to this host is dialled (an
                    // evicted https entry can hand the host back to plain http
                    // under Auto mode).
                    warn_once_or_info!(
                        "splice proxy: evicted cached {scheme} scheme for host {} after connect failure; the next request re-decides the scheme",
                        mirror.format_authority()
                    );
                }
                if decision.is_upgrade_attempt() {
                    metrics::HTTPS_UPGRADE_FAILED.increment();
                }
            }
            return Err(UpstreamFailure {
                err: err.err,
                logged,
            });
        };
        debug!(
            "splice proxy: failed to connect to {host_authority} after {attempt} connection attempts, will retry in {} ms:  {}",
            delay.as_millis(),
            ErrorReport(&err.err)
        );
        tokio::time::sleep(delay).await;
    };
    if let Some(decision) = decision {
        cache_scheme(mirror, scheme);
        // Loop-exit upgrade outcome: HTTPS connected → SUCCEEDED; fell back to
        // HTTP → REVERTED.
        if decision.is_upgrade_attempt() {
            match scheme {
                Scheme::Https => metrics::HTTPS_UPGRADE_SUCCEEDED.increment(),
                Scheme::Http => metrics::HTTPS_UPGRADE_REVERTED.increment(),
            }
        }
    }

    let is_tls = up.is_tls();

    let (resp, hdr_buf, hdr_end) = send_and_read_headers(
        &mut up,
        host_authority,
        upstream_path,
        resume_offset,
        resume_if_range,
        volatile_cond,
    )
    .await
    .map_err(|err| {
        let logged = warn_once_or_info_logged!(
            "splice proxy: failed upstream request to {host_authority} for {upstream_path}; returning 502:  {}",
            ErrorReport(&err)
        );
        UpstreamFailure { err, logged }
    })?;

    let poolable = !resp.connection_close;
    let port = mirror_port(mirror, is_tls);
    Ok(UpstreamExchange {
        conn: PoolGuard::new(up, mirror.host().to_string(), port, poolable),
        response: resp,
        header_buf: hdr_buf,
        header_end: hdr_end,
        reused: false,
    })
}

/// Follow a 3xx redirect if the Location target is valid and allowed.
///
/// On success, replaces `exchange` (connection, response, header buffer and
/// TLS label) with the redirected request's exchange, and returns
/// `Some(redirected_path)`. If the redirect is not followable (invalid URI,
/// disallowed host), logs and returns `None` so the caller falls through to the
/// non-200 forwarding path.
///
/// Times out after the configured HTTP timeout.
pub(super) async fn follow_redirect(
    exchange: &mut UpstreamExchange,
    conn_details: &ConnectionDetails,
    original_path: &str,
    resume_offset: u64,
    resume_if_range: Option<&str>,
    volatile_cond: Option<&VolatileCondHeaders>,
) -> Result<Option<String>, SpliceProxyError> {
    let status = exchange.response.status_code;
    let Some(location) = exchange.response.location.as_deref() else {
        // Every other reject branch below logs; without this one a broken
        // upstream's 3xx is forwarded to the client with nothing cached and
        // no explanation anywhere.
        warn_once_or_info!(
            "splice proxy: upstream {} answered {status} for {} without a Location header; forwarding the redirect to the client uncached",
            conn_details.mirror,
            conn_details.debname
        );
        return Ok(None);
    };
    let Ok(moved_uri) = location.parse::<http::Uri>() else {
        debug!(
            "splice proxy: {status} with unparsable Location `{}`, not following",
            location.escape_debug()
        );
        return Ok(None);
    };
    if moved_uri.scheme().is_none() {
        // A relative Location (`/pool/...`) is legal per RFC 9110 and common
        // on redirectors, but this backend only follows absolute targets, so
        // the resource is forwarded uncached on every request. Checked before
        // the scheme branch below, which would otherwise report a relative
        // target as a non-HTTP scheme.
        warn_once_or_info!(
            "splice proxy: upstream {} sent {status} for {} with relative Location `{}`; not following the redirect and not caching the response",
            conn_details.mirror,
            conn_details.debname,
            location.escape_debug()
        );
        return Ok(None);
    }
    let Some(redirect_scheme) = moved_uri.scheme().and_then(Scheme::from_uri_scheme) else {
        debug!("splice proxy: {status} redirect to non-HTTP scheme `{moved_uri}`, not following");
        return Ok(None);
    };
    let Some(moved_host) = moved_uri.host() else {
        debug!("splice proxy: {status} redirect target `{moved_uri}` has no host, not following");
        return Ok(None);
    };
    if !is_host_allowed_cached(moved_host) {
        debug!(
            "splice proxy: {status} redirect host `{moved_host}` not in allowed_mirrors, not following"
        );
        return Ok(None);
    }
    let Ok(moved_domain) = ClientHost::new(moved_host.to_owned()) else {
        // Upstream-controlled and per request, like its sibling branches.
        warn_once_or_info!(
            "splice proxy: upstream {} sent {status} for {} with an invalid redirect host `{}`; not following the redirect and not caching the response",
            conn_details.mirror,
            conn_details.debname,
            moved_host.escape_debug()
        );
        return Ok(None);
    };

    // Reject self-redirects: if the target (host, port, path) matches the request
    // we just made, following it would just repeat the same request and create
    // unnecessary load (and potentially loop on a misconfigured mirror).
    let moved_path = moved_uri
        .path_and_query()
        .map_or("/", http::uri::PathAndQuery::as_str);
    let moved_port_effective = moved_uri.port_u16().unwrap_or_else(|| {
        if moved_uri.scheme() == Some(&http::uri::Scheme::HTTPS) {
            443
        } else {
            80
        }
    });
    let original_port_effective = mirror_port(&conn_details.mirror, exchange.conn.is_tls());
    if moved_host == conn_details.mirror.host()
        && moved_port_effective == original_port_effective
        && moved_path == original_path
    {
        debug!(
            "splice proxy: {status} redirect target `{moved_uri}` matches original request, not following"
        );
        return Ok(None);
    }

    debug!(
        "splice proxy: following {status} redirect from {} to {moved_uri}",
        conn_details.mirror
    );

    // Mark as non-poolable so the old connection is discarded (not returned to
    // pool) when we reassign `*exchange` below.
    exchange.conn.unset_poolable();

    let moved_port = moved_uri.port_u16().and_then(NonZero::new);
    // Redirect Mirror: used only for upstream dispatch/formatting; never persisted.
    let redirect_mirror = Mirror::new(
        moved_domain,
        moved_port,
        String::new(),
        MirrorKind::Structured,
    );
    let redirect_authority = redirect_mirror.format_authority();
    let redirect_path = moved_path;

    *exchange = standard_upstream_connect(
        &redirect_mirror,
        &redirect_authority,
        redirect_path,
        resume_offset,
        resume_if_range,
        volatile_cond,
        Some(redirect_scheme),
    )
    .await
    .map_err(|err| {
        // The throw site inside `standard_upstream_connect` already WARNs
        // with the underlying error detail (the `UpstreamFailure` carries the
        // proof); this line adds the redirect breadcrumb so an operator can
        // correlate the connect failure with the redirect that pointed at
        // the now-failing target.
        warn_once_or_info!(
            "splice proxy: failed to connect to the upstream after a {status} redirect from {} to `{moved_uri}`; returning 502",
            conn_details.mirror
        );
        SpliceProxyError::Upstream(err)
    })?;

    Ok(Some(redirect_path.to_owned()))
}

/// Log an upstream response the planner rejected (`DownloadPlan::Reject`).
///
/// `origin` tags the kTLS one-shot attempt (`" (from kTLS attempt)"`) or is
/// empty.  Wording mirrors `hyper_conn.rs::serve_new_file` modulo the
/// subsystem prefix.
pub(super) fn warn_upstream_reject(
    reason: RejectReason,
    conn_details: &ConnectionDetails,
    origin: &str,
) {
    match reason {
        RejectReason::Unsolicited206 => warn_once_or_info!(
            "splice proxy: upstream returned 206 Partial Content without a Range request for {} from mirror {}{origin}; returning 502",
            conn_details.debname,
            conn_details.mirror
        ),
        RejectReason::InconsistentContentRange {
            content_length,
            span,
        } => warn_once_or_info!(
            "splice proxy: Content-Length {content_length} disagrees with Content-Range span {span} for {} from mirror {}{origin}; returning 502",
            conn_details.debname,
            conn_details.mirror
        ),
        RejectReason::Oversize { total } => warn_once_or_info!(
            "splice proxy: upstream declared total size {} for file {} from mirror {}{origin}, exceeding `max_object_size`; returning 502",
            HumanFmt::Size(total),
            conn_details.debname,
            conn_details.mirror
        ),
        RejectReason::NoContentLength => warn_once_or_info!(
            "splice proxy: upstream sent no usable Content-Length for file {} from mirror {}{origin}; returning 502",
            conn_details.debname,
            conn_details.mirror
        ),
        RejectReason::ZeroContentLength => warn_once_or_info!(
            "splice proxy: upstream declared Content-Length 0 for file {} from mirror {}{origin}; returning 502",
            conn_details.debname,
            conn_details.mirror
        ),
    }
}

/// Discard a stale partial download file and retry the upstream request from scratch.
///
/// Shared by the 416 and invalid-Content-Range recovery paths
/// (`ResumeAnomaly::needs_refetch`).
pub(super) async fn discard_partial_and_retry(
    partial: &mut utils::PartialDownload,
    mirror: &Mirror,
    host_authority: &str,
    upstream_path: &str,
    exchange: &mut UpstreamExchange,
    conn_details: &ConnectionDetails,
) -> Result<(), SpliceProxyError> {
    partial.discard_resume().await;
    exchange.conn.unset_poolable();
    *exchange =
        standard_upstream_connect(mirror, host_authority, upstream_path, 0, None, None, None)
            .await
            .map_err(SpliceProxyError::Upstream)?;
    // The fresh connect above does not follow redirects; the caller's top-level
    // redirect handling already ran on the original (now-discarded) response, so
    // follow one redirect here if the retry also lands on a 3xx (the retry is
    // always a fresh full request: resume_offset=0, no If-Range/volatile cond).
    if matches!(
        exchange.response.status_code,
        StatusCode::MOVED_PERMANENTLY
            | StatusCode::FOUND
            | StatusCode::TEMPORARY_REDIRECT
            | StatusCode::PERMANENT_REDIRECT
    ) {
        follow_redirect(exchange, conn_details, upstream_path, 0, None, None).await?;
    }
    Ok(())
}

/// Acquire the upstream exchange for a cache-miss download.
///
/// Under `ktls` the unbuffered kTLS attempt runs first (connect + handshake +
/// request + response headers in one shot with guaranteed record alignment)
/// and falls back to [`standard_upstream_connect`] on any failure or on a
/// response it cannot splice -- except for the two responses resolvable from
/// the already-buffered head alone (a planner-rejected 200, a 304 with a
/// cached copy), which come back as their own [`UpstreamAcquire`] variants so
/// no reconnect is spent on them. Without `ktls` this is
/// `standard_upstream_connect`.
///
/// Times out after the configured HTTP timeout.
pub(super) async fn acquire_upstream(
    conn_details: &ConnectionDetails,
    host_authority: &str,
    upstream_path: &str,
    resume_offset: u64,
    resume_if_range: Option<&str>,
    volatile_cond: Option<&VolatileCondHeaders>,
    #[cfg(feature = "ktls")] volatile_cache_path: &mut Option<PathBuf>,
) -> Result<UpstreamAcquire, SpliceProxyError> {
    let mirror = &conn_details.mirror;

    #[cfg(feature = "ktls")]
    {
        let unbuffered_result = try_unbuffered_ktls_connect(
            mirror,
            host_authority,
            upstream_path,
            resume_offset,
            resume_if_range,
            volatile_cond,
        )
        .await;

        // Handle kTLS ResponseNotSpliceable early for cases we can fully resolve
        // from the already-buffered data (304 -> serve cache, 200-without-CL non-volatile
        // -> 502). Everything else falls through to the standard path, which reconnects
        // to deliver a complete response rather than forwarding a potentially truncated
        // body from the one-shot kTLS attempt.
        if let KtlsResult::ResponseNotSpliceable { ref response, .. } = unbuffered_result {
            cache_scheme(mirror, Scheme::Https);
            if response.status_code == 200 {
                // A 200 the kTLS path could not splice has no usable
                // Content-Length (absent, chunked or zero).  The planner refuses
                // what it would refuse on the standard path too (permanent files,
                // `Content-Length: 0`) without a reconnect; a volatile file falls
                // through to the standard path for a buffered download, whose
                // reconnect bumps `record_upstream_status` itself.
                match plan_fresh_download::<PathBuf>(
                    &response.head(),
                    conn_details.cached_flavor(),
                    None,
                    global_config().max_object_size,
                ) {
                    DownloadPlan::Reject(reason) => {
                        reason.record_metrics();
                        warn_upstream_reject(reason, conn_details, " (from kTLS attempt)");
                        // Honoring the kTLS-parsed response: record its status before
                        // the caller emits our own 502 to the client. (The standard
                        // path is not reconnected for, so no other site will record
                        // this 200.)
                        metrics::record_upstream_status(response.status_code);
                        return Ok(UpstreamAcquire::KtlsReject(reason));
                    }
                    DownloadPlan::NotModified(_)
                    | DownloadPlan::Passthrough
                    | DownloadPlan::Download { .. } => {
                        debug!(
                            "splice proxy: volatile file without Content-Length (from kTLS attempt), \
                             falling back to standard path for buffered download"
                        );
                    }
                }
            }
            // During resume, 206 and 416 need the standard buffered path
            if resume_offset > 0 && (response.status_code == 206 || response.status_code == 416) {
                debug!(
                    "splice proxy: kTLS got {} during resume, falling back to standard path",
                    response.status_code
                );
                // Fall through to standard_upstream_connect via the ResponseNotSpliceable arm below
            } else if response.status_code == 304
                && let Some(cache_path) = volatile_cache_path.take()
            {
                // 304 from kTLS for volatile resource -- the caller serves the cached
                // file directly rather than reconnecting on the standard path just to
                // get the same 304.
                debug!(
                    "splice proxy: kTLS upstream returned 304 for {} from mirror {}, serving cached file",
                    conn_details.debname, conn_details.mirror
                );

                // Honoring the kTLS-parsed 304: record its upstream status here
                // since no standard-path reconnect will run for this response.
                metrics::record_upstream_status(response.status_code);

                return Ok(UpstreamAcquire::KtlsNotModified(cache_path));
            } else {
                // Non-200 / no-Content-Length response from the kTLS attempt.
                // We cannot safely forward just the buffered bytes: the body may be
                // longer than what rustls already decrypted, and the kTLS connection
                // has been consumed for a single request -- there is no userspace read
                // loop to pull the remainder. Falling through to the standard path
                // reconnects and re-fetches, which delivers a complete response to
                // the client. One extra request is cheaper than a truncated reply.
                debug!(
                    "splice proxy: upstream returned {} (from kTLS attempt), reconnecting via standard path",
                    response.status_code
                );
                // Fall through to the `ResponseNotSpliceable { .. }` match arm below,
                // which leads to standard_upstream_connect().
            }
        }

        match unbuffered_result {
            KtlsResult::Ready(tcp, state) => {
                // The kTLS fast path is outside HTTPS_UPGRADE_* accounting (see
                // metrics.rs); both sides of the identity are skipped together.
                cache_scheme(mirror, Scheme::Https);
                // Wrapped as `UpstreamConn::Ktls`, which `PoolGuard::drop`
                // never returns to the pool (the rationale lives there); the
                // keep-alive bit is recorded like on the standard path.
                let port = mirror_port(mirror, true);
                // Honoring the kTLS-parsed response: record its upstream status
                // here since no standard-path reconnect will run for this flow.
                metrics::record_upstream_status(state.response.status_code);
                let KtlsReadyState {
                    response,
                    header_buf,
                    header_end,
                } = state;
                let poolable = !response.connection_close;
                return Ok(UpstreamAcquire::Exchange(UpstreamExchange {
                    conn: PoolGuard::new(
                        UpstreamConn::Ktls(tcp),
                        mirror.host().to_string(),
                        port,
                        poolable,
                    ),
                    response,
                    header_buf,
                    header_end,
                    reused: false,
                }));
            }
            KtlsResult::ResponseNotSpliceable { response: _ } => {
                // Normally handled above, but during resume 206/416 fall through here
                // to use the standard buffered path for proper resume handling.
                // A full reconnect, not a reuse of the kTLS socket: that socket is
                // already dropped and would be unsound to reuse (KtlsResult contract).
            }
            KtlsResult::Failed { tls_succeeded } => {
                // Cache HTTPS scheme if TLS handshake succeeded, avoiding double-HTTPS
                // in auto mode
                if tls_succeeded {
                    cache_scheme(mirror, Scheme::Https);
                }
            }
        }
    }

    standard_upstream_connect(
        mirror,
        host_authority,
        upstream_path,
        resume_offset,
        resume_if_range,
        volatile_cond,
        None,
    )
    .await
    .map(UpstreamAcquire::Exchange)
    .map_err(SpliceProxyError::Upstream)
}
