//! Acquiring an upstream exchange for a cache-miss download:
//! [`standard_upstream_connect`] owns the retry/backoff envelope over pool
//! checkout + connect + send + read-headers, [`follow_redirect`] and
//! [`discard_partial_and_retry`] replace the exchange on a redirect or a
//! non-resumable partial. The result is an [`UpstreamExchange`] (connection,
//! parsed head, header buffer and body-prefix boundary).
//!
//! Consumers: the drive in `mod.rs`, `simple_proxy` and `cleanup_bridge`
//! (`standard_upstream_connect`), plus the drive's reconnect helpers and
//! `warn_upstream_reject`.

use std::{num::NonZero, time::Duration};

use bytes::BytesMut;
use tracing::debug;

use crate::cache_layout::ConnectionDetails;
use crate::config::ClientHost;
use crate::deb_mirror::{Mirror, MirrorKind};
use crate::error::ErrorReport;
use crate::partial_file;
use crate::scheme_cache::SchemeDecision;
use crate::upstream_head::{RejectGates, RejectReason};
use crate::{
    Scheme, global_config, log_once, metrics, permitted_host_cache::is_host_allowed_cached,
    scheme_cache, upstream_retry, warn_once_or_info, warn_once_or_info_logged,
};

use super::http::{
    BodyFraming, HeadError, MAX_ERROR_BODY_DRAIN, UpstreamResponse, send_and_read_headers,
};
use super::upstream::{
    ConnLabel, PoolCheckout, ResponseBody, Transience, UpstreamConn, connect_upstream, mirror_port,
    pool_checkout,
};
use super::{SpliceProxyError, UpstreamFailure, VolatileCondHeaders};

/// One upstream request/response in flight: the pool-guarded connection the
/// response arrived on, its parsed head, and the bytes read alongside it
/// (`header_buf[header_end..]` is the body prefix). Built only by
/// [`standard_upstream_connect`] and replaced wholesale by the reconnect helpers
/// ([`follow_redirect`], [`discard_partial_and_retry`]), so every field always
/// describes the same connection.
pub(super) struct UpstreamExchange {
    pub(super) conn: ResponseBody,
    pub(super) response: UpstreamResponse,
    pub(super) header_buf: BytesMut,
    pub(super) header_end: usize,
    /// Whether `conn` came out of the pool rather than a fresh connect.
    pub(super) reused: bool,
}

impl UpstreamExchange {
    /// Wrap the head [`send_and_read_headers`] returned on `conn` into an
    /// exchange; dropping it closes the connection until body completion.
    fn new(
        conn: UpstreamConn,
        mirror: &Mirror,
        port: u16,
        (response, header_buf, header_end): (UpstreamResponse, BytesMut, usize),
        reused: bool,
    ) -> Self {
        let poolable = !response.connection_close;
        Self {
            conn: ResponseBody::new(conn, mirror.host().clone(), port, poolable),
            response,
            header_buf,
            header_end,
            reused,
        }
    }

    /// Consume an abandoned response, returning its connection only if its
    /// body can be drained within a small byte and total-time budget. The
    /// caller can then acquire a replacement without leaving a live exchange
    /// containing an empty connection guard.
    ///
    /// Close-delimited and explicitly closing responses are dropped at once.
    /// Timeout/error cancellation drops the response owner, so a partial drain
    /// can never make the connection reusable.
    pub(super) async fn dispose(self, log_prefix: &str) {
        const MAX_DRAIN_TIME: Duration = Duration::from_millis(250);

        let Self {
            conn,
            response,
            header_buf,
            header_end,
            reused: _,
        } = self;
        if !conn.permits_reuse() || response.framing == BodyFraming::CloseDelimited {
            return;
        }

        let result = tokio::time::timeout(
            MAX_DRAIN_TIME,
            response
                .framing
                .read_to_vec(conn, &header_buf[header_end..], MAX_ERROR_BODY_DRAIN),
        )
        .await;
        match result {
            Ok(Ok(_body)) => {}
            Ok(Err(err)) => debug!(
                "{log_prefix} not reusing the upstream connection after a {} response, its body could not be drained:  {}",
                response.status_code,
                ErrorReport(&err)
            ),
            Err(_timeout @ tokio::time::error::Elapsed { .. }) => {
                debug!(
                    "{log_prefix} not reusing the upstream connection after a {} response, its body exceeded the {} ms drain budget",
                    response.status_code,
                    MAX_DRAIN_TIME.as_millis()
                );
            }
        }
        // The body reader returns only a fully consumed, reusable connection.
    }

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
            tls: conn.is_tls(),
            reused: *reused,
        }
    }
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

/// Standard upstream connect→request→read-headers→parse pipeline.
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
        match pool_checkout(mirror.host(), port, is_tls) {
            PoolCheckout::Live(mut pooled) => {
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
                    Ok(head) => {
                        metrics::POOL_REUSED.increment();
                        return Ok(UpstreamExchange::new(pooled, mirror, port, head, true));
                    }
                    Err(HeadError::Transport(err)) => {
                        // The pooled socket's fault (the peer hung up between
                        // the liveness probe and the head, a NAT dropped the
                        // idle flow, the TLS session failed): worth one fresh
                        // connection.
                        metrics::POOL_MISS_FAILED.increment();
                        debug!(
                            "splice proxy: pooled connection to {host_authority} failed, \
                             opening fresh:  {}",
                            ErrorReport(&err)
                        );
                    }
                    Err(HeadError::Protocol(err)) => {
                        // The upstream's answer is broken, not the socket: a
                        // fresh connection would fetch the same bytes.
                        return Err(failed_request(host_authority, upstream_path, err));
                    }
                }
            }
            PoolCheckout::Dead => {
                metrics::POOL_MISS_DEAD.increment();
                debug!("splice proxy: pooled connection to {host_authority} is dead, discarding");
            }
            PoolCheckout::Empty => {
                metrics::POOL_MISS_EMPTY.increment();
            }
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
        let permanent = err.transience == Transience::Permanent;
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

    let head = send_and_read_headers(
        &mut up,
        host_authority,
        upstream_path,
        resume_offset,
        resume_if_range,
        volatile_cond,
    )
    .await
    .map_err(|err| failed_request(host_authority, upstream_path, err.into_io()))?;

    let port = mirror_port(mirror, up.is_tls());
    Ok(UpstreamExchange::new(up, mirror, port, head, false))
}

/// The 502 for a request whose head could not be read, on a pooled or a
/// fresh connection alike: one wording, one once-gate.
fn failed_request(
    host_authority: &str,
    upstream_path: &str,
    err: std::io::Error,
) -> UpstreamFailure {
    let logged = warn_once_or_info_logged!(
        "splice proxy: failed upstream request to {host_authority} for {upstream_path}; returning 502:  {}",
        ErrorReport(&err)
    );
    UpstreamFailure { err, logged }
}

/// Where a followed redirect landed: the mirror the retry/resume logic must
/// keep talking to, its `Host` authority and the redirected path.
pub(super) struct RedirectTarget {
    /// Used only for upstream dispatch/formatting; never persisted.
    pub(super) mirror: Mirror,
    pub(super) authority: String,
    pub(super) path: String,
}

/// Follow a 3xx redirect if the Location target is valid and allowed.
///
/// Returns the replacement exchange and the [`RedirectTarget`] it landed
/// on. If the redirect is not followable (invalid URI, disallowed host),
/// logs and returns the original exchange with `None` so the caller
/// falls through to the non-200 forwarding path.
///
/// Times out after the configured HTTP timeout.
pub(super) async fn follow_redirect(
    exchange: UpstreamExchange,
    conn_details: &ConnectionDetails,
    original_path: &str,
    resume_offset: u64,
    resume_if_range: Option<&str>,
    volatile_cond: Option<&VolatileCondHeaders>,
) -> Result<(UpstreamExchange, Option<RedirectTarget>), SpliceProxyError> {
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
        return Ok((exchange, None));
    };
    let Ok(moved_uri) = location.parse::<http::Uri>() else {
        debug!(
            "splice proxy: {status} with unparsable Location `{}`, not following",
            location.escape_debug()
        );
        return Ok((exchange, None));
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
        return Ok((exchange, None));
    }
    let Some(redirect_scheme) = moved_uri.scheme().and_then(Scheme::from_uri_scheme) else {
        debug!("splice proxy: {status} redirect to non-HTTP scheme `{moved_uri}`, not following");
        return Ok((exchange, None));
    };
    let Some(moved_host) = moved_uri.host() else {
        debug!("splice proxy: {status} redirect target `{moved_uri}` has no host, not following");
        return Ok((exchange, None));
    };
    if !is_host_allowed_cached(moved_host) {
        debug!(
            "splice proxy: {status} redirect host `{moved_host}` not in allowed_mirrors, not following"
        );
        return Ok((exchange, None));
    }
    let Ok(moved_domain) = ClientHost::new(moved_host.to_owned()) else {
        // Upstream-controlled and per request, like its sibling branches.
        warn_once_or_info!(
            "splice proxy: upstream {} sent {status} for {} with an invalid redirect host `{}`; not following the redirect and not caching the response",
            conn_details.mirror,
            conn_details.debname,
            moved_host.escape_debug()
        );
        return Ok((exchange, None));
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
    let dial_mirror = conn_details.upstream_mirror();
    let original_port_effective = mirror_port(&dial_mirror, exchange.conn.is_tls());
    if moved_host == dial_mirror.host()
        && moved_port_effective == original_port_effective
        && moved_path == original_path
    {
        debug!(
            "splice proxy: {status} redirect target `{moved_uri}` matches original request, not following"
        );
        return Ok((exchange, None));
    }

    debug!(
        "splice proxy: following {status} redirect from {} to {moved_uri}",
        conn_details.mirror
    );

    // Give the connection back before dialling the target: a redirect that
    // stays on this host (a path rewrite, a `by-hash` bounce) then reuses it.
    exchange.dispose("splice proxy:").await;

    let moved_port = moved_uri.port_u16().and_then(NonZero::new);
    // Redirect Mirror: used only for upstream dispatch/formatting; never persisted.
    let redirect_mirror = Mirror::new(
        moved_domain,
        moved_port,
        String::new(),
        MirrorKind::Structured,
    );
    let redirect_authority = redirect_mirror.format_authority();

    let exchange = standard_upstream_connect(
        &redirect_mirror,
        redirect_authority,
        moved_path,
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

    Ok((
        exchange,
        Some(RedirectTarget {
            authority: redirect_authority.to_owned(),
            path: moved_path.to_owned(),
            mirror: redirect_mirror,
        }),
    ))
}

/// Log the planner's refusal of an upstream response.
///
/// The complaint itself lives on [`RejectReason::detail`], shared with the
/// hyper backend; this owns the `splice proxy:` prefix and the once-gates.
pub(super) fn warn_upstream_reject(reason: RejectReason, conn_details: &ConnectionDetails) {
    /// One gate per reason: a mirror tripping `max_object_size` must not
    /// mute the first genuine protocol violation.
    static GATES: RejectGates = RejectGates::new();

    log_once::warn_once_or_info_gated(
        GATES.for_reason(reason),
        format_args!(
            "splice proxy: upstream response rejected for {} from mirror {}: {}; returning 502",
            conn_details.debname,
            conn_details.mirror,
            reason.detail()
        ),
    );
}

/// Discard a stale partial download file and retry the upstream request from scratch.
///
/// Shared by the 416 and invalid-Content-Range recovery paths
/// (`ResumeAnomaly::needs_refetch`).
pub(super) async fn discard_partial_and_retry(
    partial: &mut partial_file::PartialDownload,
    mirror: &Mirror,
    host_authority: &str,
    upstream_path: &str,
    exchange: UpstreamExchange,
    conn_details: &ConnectionDetails,
) -> Result<UpstreamExchange, SpliceProxyError> {
    // Try a bounded drain before refetching. Preserve the scheme used by
    // the discarded connection --
    // after a redirect it was fixed by the `Location` URL and never cached
    // for the target host, so re-deciding it (under `Auto`, an HTTPS probe
    // against a target the redirect named as `http://`) would look the
    // pooled connection up under the wrong key.
    let scheme = exchange.conn.scheme();
    exchange.dispose("splice proxy:").await;
    partial.discard_resume().await;
    let mut exchange = standard_upstream_connect(
        mirror,
        host_authority,
        upstream_path,
        0,
        None,
        None,
        Some(scheme),
    )
    .await
    .map_err(SpliceProxyError::Upstream)?;
    // The fresh connect above does not follow redirects; the caller's top-level
    // redirect handling already ran on the original (now-discarded) response, so
    // follow one redirect here if the retry also lands on a 3xx (the retry is
    // always a fresh full request: resume_offset=0, no If-Range/volatile cond).
    if exchange.response.is_redirect() {
        (exchange, _) = Box::pin(follow_redirect(
            exchange,
            conn_details,
            upstream_path,
            0,
            None,
            None,
        ))
        .await?;
    }
    Ok(exchange)
}
