//! The collapsed Metrics section of the dashboard: every counter in
//! `metrics.rs`, split into titled subsections with the alert/warn policy
//! applied per row.
//!
//! Two rules keep this readable, because a flat list of ~150 counters (of
//! which nearly all read zero on a healthy daemon) buries the handful that
//! are moving:
//!
//! - one number per cell. A label that has to enumerate its value's
//!   positions (`(current / max, peak, sent, full-waits, ...)`) is a legend,
//!   and a legend means the cell is really several cells. Genuine ratios
//!   (`hits / misses`, `requests -> served`) stay together, because there the
//!   pairing is the metric.
//! - every counter belongs to exactly one [`Groups::group`]. Adding a
//!   counter means choosing its subsection.

use std::fmt::{self, Display, Formatter};

use crate::{
    database_task::DB_TASK_QUEUE_SENDER, global_checksum_registry, global_verify_throttle,
    humanfmt::HumanFmt, metrics, swrite, tunnel_limiter::active_tunnels,
    uncacheables::UNCACHEABLES_MAX,
};

use super::{
    fmt::{AlertNonzero, Colorize, RatioClass, WarnNonzero, alert_if, warn_if},
    table::DetailsList,
};

/// Percentage suffix rendered only when the total is non-zero.
struct OptPctSuffix {
    num: u64,
    total: u64,
}
impl Display for OptPctSuffix {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        if self.total == 0 {
            Ok(())
        } else {
            #[expect(clippy::cast_precision_loss, reason = "only for display purposes")]
            let pct = self.num as f64 / self.total as f64 * 100.0;
            write!(f, " ({pct:.1}%)")
        }
    }
}

/// `req/conn` suffix rendered only when connections have been accepted.
struct OptReqPerConn {
    requests: u64,
    connections: u64,
}
impl Display for OptReqPerConn {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        if self.connections == 0 {
            Ok(())
        } else {
            #[expect(clippy::cast_precision_loss, reason = "only for display purposes")]
            let r = self.requests as f64 / self.connections as f64;
            write!(f, " ({r:.2} req/conn)")
        }
    }
}

/// The Metrics section as a run of titled subsections, each a heading
/// followed by the [`DetailsList`] its closure fills in.
struct Groups {
    out: String,
}

impl Groups {
    fn new() -> Self {
        Self {
            // The full metrics section is comfortably past 20 KB of markup.
            out: String::with_capacity(32 * 1024),
        }
    }

    fn group(&mut self, title: &'static str, build: impl FnOnce(&mut DetailsList)) {
        let mut list = DetailsList::new();
        build(&mut list);
        swrite!(
            self.out,
            "<h4 class=\"group\">{title}</h4>{}",
            list.finish()
        );
    }

    fn finish(self) -> String {
        self.out
    }
}

/// The two cells a delivery path contributes: its request-to-served funnel
/// and the bytes it moved.
fn delivery_path(
    t: &mut DetailsList,
    requests_label: &'static str,
    bytes_label: &'static str,
    tip: &'static str,
    requests: u64,
    served: u64,
    bytes: u64,
) {
    t.row_tip(
        requests_label,
        tip,
        format_args!(
            "{requests} \u{2192} {}{}",
            alert_if(served, served > requests),
            OptPctSuffix {
                num: served,
                total: requests,
            },
        ),
    );
    t.row(bytes_label, HumanFmt::Size(bytes));
}

pub(super) fn build_metrics_html() -> String {
    let mut g = Groups::new();

    build_requests_group(&mut g);
    build_cache_group(&mut g);
    build_integrity_group(&mut g);
    build_delivery_group(&mut g);
    build_upstream_group(&mut g);
    build_tunnels_group(&mut g);
    build_cleanup_group(&mut g);
    build_database_group(&mut g);
    build_errors_group(&mut g);

    g.finish()
}

fn build_requests_group(g: &mut Groups) {
    let requests_total = metrics::REQUESTS_TOTAL.get();
    let served_total = metrics::SERVED_TOTAL.get();
    let webui_requests = metrics::WEBUI_REQUESTS.get();
    let served_webui = metrics::SERVED_WEBUI.get();
    let connections_accepted = metrics::CONNECTIONS_ACCEPTED.get();

    let status_2xx = metrics::CLIENT_STATUS_2XX.get();
    let status_200 = metrics::CLIENT_STATUS_200.get();
    let status_206 = metrics::CLIENT_STATUS_206.get();
    let status_3xx = metrics::CLIENT_STATUS_3XX.get();
    let status_304 = metrics::CLIENT_STATUS_304.get();

    g.group("Requests", |t| {
        t.row_tip(
            "Requests \u{2192} Served",
            "Total HTTP requests handled \u{2192} requests whose response body was fully delivered to the client.",
            format_args!(
                "{requests_total} \u{2192} {}{}",
                alert_if(served_total, served_total > requests_total),
                OptPctSuffix {
                    num: served_total,
                    total: requests_total,
                },
            ),
        );
        t.row_tip(
            "Web UI Requests \u{2192} Served",
            "The same split for the local web interface.",
            format_args!(
                "{webui_requests} \u{2192} {}{}",
                alert_if(served_webui, served_webui > webui_requests),
                OptPctSuffix {
                    num: served_webui,
                    total: webui_requests,
                },
            ),
        );
        t.row_tip(
            "Connections Accepted",
            "TCP connections accepted from clients since the daemon started, and the resulting requests-per-connection ratio.",
            format_args!(
                "{connections_accepted}{}",
                OptReqPerConn {
                    requests: requests_total,
                    connections: connections_accepted,
                },
            ),
        );
        t.row_tip(
            "Connections Rejected (global cap)",
            "Connections dropped at accept time because `max_connections` was reached. Climbing values mean a flood or a cap sized below the real client population.",
            WarnNonzero(metrics::CONNECTION_REJECTED_GLOBAL_CAP.get()),
        );
        t.row_tip(
            "Connections Rejected (per-IP cap)",
            "Plain-HTTP connections dropped at accept time because `max_connections_per_client_ip` was reached. Stays at 0 unless the cap is configured; climbing values point to a noisy or malicious source IP.",
            WarnNonzero(metrics::CONNECTION_REJECTED_PER_IP_CAP.get()),
        );
        t.row_tip(
            "Accept Failures (retried)",
            "accept(2) failures retried after a short pause instead of stopping the daemon: descriptor exhaustion (EMFILE/ENFILE), ENOBUFS/ENOMEM, ECONNABORTED. Climbing values mean the process is at its file-descriptor budget.",
            WarnNonzero(metrics::ACCEPT_TRANSIENT_FAILURES.get()),
        );
        t.row_tip(
            "Read Failures (peer disconnect)",
            "Header-read failures before any request was parsed, from a normal client close between keep-alive requests.",
            metrics::REQUEST_READ_PEER_DISCONNECT.get(),
        );
        t.row_tip(
            "Read Failures (protocol error)",
            "Header-read failures from oversized or malformed headers. This is the abuse signal, unlike the peer-disconnect counter beside it.",
            WarnNonzero(metrics::REQUEST_READ_PROTOCOL_ERROR.get()),
        );
        t.row_tip(
            "Unhandled Request Headers",
            "Requests carrying an HTTP header outside the daemon's known set, on the upstream-relay path. Useful as a first-contact discovery signal; the log line itself is debounced.",
            WarnNonzero(metrics::UNHANDLED_REQUEST_HEADERS.get()),
        );
        t.row_tip(
            "Client Disconnected Mid-Body",
            "Clients that disconnected before the response body was fully delivered.",
            metrics::CLIENT_DISCONNECTED_MID_BODY.get(),
        );
        t.row_tip(
            "Timeouts (client header read)",
            "Configured-timeout firings while reading a client's request headers.",
            metrics::HTTP_TIMEOUT_CLIENT_HEADER.get(),
        );
        t.row_tip(
            "Timeouts (client header write)",
            "Configured-timeout firings while writing response headers to a client.",
            metrics::HTTP_TIMEOUT_CLIENT_HEADER_WRITE.get(),
        );
        t.row_tip(
            "Timeouts (client body write)",
            "Configured-timeout firings while writing a response body to a client.",
            metrics::HTTP_TIMEOUT_CLIENT_BODY.get(),
        );

        t.row_tip(
            "Client 2xx",
            "Successful responses returned to clients. Warns when the class total does not match the 200 and 206 counters below it.",
            warn_if(status_2xx, status_2xx != status_200 + status_206),
        );
        t.row_tip(
            "Client 3xx",
            "Redirect and not-modified responses returned to clients. Warns when the class total does not match the 304 counter below it.",
            warn_if(status_3xx, status_3xx != status_304),
        );
        t.row_tip(
            "Client 4xx",
            "Client-error responses. Not warned on: pdiff rejections and web-interface 404 probes land here routinely.",
            metrics::CLIENT_STATUS_4XX.get(),
        );
        t.row_tip(
            "Client 5xx",
            "Server-error responses returned to clients.",
            AlertNonzero(metrics::CLIENT_STATUS_5XX.get()),
        );
        t.row_tip(
            "Client Other",
            "Responses outside the 2xx-5xx classes.",
            WarnNonzero(metrics::CLIENT_STATUS_OTHER.get()),
        );
        t.row("Client 200 OK", status_200);
        t.row("Client 206 Partial Content", status_206);
        t.row("Client 304 Not Modified", status_304);
        t.row("Client 410 Gone", metrics::CLIENT_STATUS_410.get());
        t.row(
            "Client 416 Range Not Satisfiable",
            metrics::CLIENT_STATUS_416.get(),
        );

        t.row_tip(
            "Rejected (pdiff)",
            "Client requests for pdiff resources, refused because `reject_pdiff_requests` is set.",
            metrics::PDIFF_REJECTED.get(),
        );
        t.row_tip(
            "Rejected (unsafe path)",
            "Client requests refused because their path failed the traversal and encoding checks.",
            WarnNonzero(metrics::UNSAFE_PATH_REJECTED.get()),
        );
        t.row_tip(
            "Rejected (quota reached)",
            "Downloads denied because the configured disk quota is exhausted.",
            WarnNonzero(metrics::DOWNLOAD_REJECTED_QUOTA.get()),
        );
        t.row_tip(
            "Rejected (oversize)",
            "Downloads refused because the upstream object size exceeded `max_object_size`.",
            WarnNonzero(metrics::DOWNLOAD_REJECTED_OVERSIZE.get()),
        );
        t.row_tip(
            "Rejected (verify-throttled)",
            "Downloads refused because the resource recently failed checksum verification.",
            WarnNonzero(metrics::DOWNLOAD_REJECTED_VERIFY_THROTTLE.get()),
        );
        t.row_tip(
            "Proxy Loops Rejected",
            "Requests refused with 508 because their `Via` already named this proxy. Any value means an `allowed_mirrors` wildcard covers the proxy's own name.",
            WarnNonzero(metrics::PROXY_LOOP_REJECTED.get()),
        );
        t.row_tip(
            "Authorization Rejected (mirror)",
            "Requests refused because the requested mirror is outside `allowed_mirrors`.",
            metrics::AUTHZ_REJECTED_MIRROR.get(),
        );
        t.row_tip(
            "Authorization Rejected (client)",
            "Requests refused because the source address is outside `allowed_proxy_clients`.",
            metrics::AUTHZ_REJECTED_CLIENT.get(),
        );
        t.row_tip(
            "Authorization Rejected (tunnel mirror)",
            "CONNECT requests refused because the target is outside `https_tunnel_allowed_mirrors`.",
            metrics::AUTHZ_REJECTED_TUNNEL_MIRROR.get(),
        );
        t.row_tip(
            "Authorization Rejected (web interface)",
            "Web-interface requests refused because the source address is outside `allowed_webif_clients`.",
            metrics::AUTHZ_REJECTED_WEBUI.get(),
        );
    });
}

fn build_cache_group(g: &mut Groups) {
    let hits = metrics::CACHE_HITS.get();
    let misses = metrics::CACHE_MISSES.get();
    let lookups = hits + misses;
    let refetched = metrics::VOLATILE_REFETCHED.get();
    let refetched_uptodate = metrics::VOLATILE_REFETCHED_UPTODATE.get();
    let refetched_outofdate = metrics::VOLATILE_REFETCHED_OUTOFDATE.get();

    g.group("Cache", |t| {
        t.row_tip(
            "Hits / Misses",
            "Cache lookups for permanent (non-volatile) resources that found a usable file vs. those that did not.",
            format_args!(
                "{hits} / {misses}{}",
                OptPctSuffix {
                    num: hits,
                    total: lookups,
                },
            ),
        );
        t.row_tip(
            "Volatile Hits",
            "Volatile-resource (Release/Packages/Translation/...) cache hits within the freshness window.",
            metrics::VOLATILE_HIT.get(),
        );
        t.row_tip(
            "Volatile Refetches",
            "Volatile resources revalidated against upstream. Warns only on the impossible direction: the two outcome counters beside it cover the stale-but-present case only, so a refetch total below their sum is a counting bug.",
            // Subset invariant: UPTODATE + OUTOFDATE only count the
            // stale-but-present case; the volatile-not-found case bumps
            // REFETCHED without either subset, so REFETCHED >= sum is the
            // true invariant.
            warn_if(refetched, refetched < refetched_uptodate + refetched_outofdate),
        );
        t.row_tip(
            "Refetch Up-to-Date (304)",
            "Revalidations where upstream confirmed the cached copy was still current.",
            refetched_uptodate,
        );
        t.row_tip(
            "Refetch Out-of-Date (200)",
            "Revalidations where upstream returned changed content.",
            refetched_outofdate,
        );
        t.row_tip(
            "Uncacheable Evictions",
            "Recent uncacheable (host, path) entries evicted from the in-memory ring buffer because of overflow.",
            WarnNonzero(
                metrics::UNCACHEABLE
                    .get()
                    .saturating_sub(UNCACHEABLES_MAX.get() as u64),
            ),
        );
        t.row_tip(
            "Reconcile Events",
            "Cache reconciliation events that repaired on-disk size accounting.",
            metrics::RECONCILE_EVENTS.get(),
        );
        t.row_tip(
            "Reconcile Bytes Repaired",
            "Total size-accounting error corrected by those reconciliation events.",
            HumanFmt::Size(metrics::RECONCILE_BYTES_REPAIRED.get()),
        );
        t.row_tip(
            "Size Accounting Corruption",
            "Overflow or underflow detected in the in-memory total-cache-size accounting (value clamped; repaired by the next reconcile).",
            AlertNonzero(metrics::CACHE_SIZE_CORRUPTION.get()),
        );
    });
}

fn build_integrity_group(g: &mut Groups) {
    g.group("Integrity", |t| {
        t.row_tip(
            "Verified",
            "Downloaded resources (pool .debs, by-hash files, Packages indices) whose content hash matched a known digest.",
            metrics::CHECKSUM_VERIFIED.get(),
        );
        t.row_tip(
            "Mismatch (rejected)",
            "Resources rejected because their content hash did not match the expected digest. Non-zero indicates a corrupt or tampered upstream response.",
            AlertNonzero(metrics::CHECKSUM_MISMATCH.get()),
        );
        t.row_tip(
            "Unverified (no known digest)",
            "Resources for which no expected digest was available in the registry; cached unverified (best-effort).",
            metrics::CHECKSUM_UNVERIFIED.get(),
        );
        t.row_tip(
            "Registry Entries",
            "In-memory checksum-registry entries (expected digests parsed from Packages/Release indices; lost on restart).",
            global_checksum_registry().len(),
        );
        t.row_tip(
            "Throttled Resources",
            "Resources currently rejected with 503 because a recent download failed checksum verification (exponential backoff; cleared by a successfully verified download).",
            WarnNonzero(global_verify_throttle().active_len() as u64),
        );
    });
}

fn build_delivery_group(g: &mut Groups) {
    g.group("Delivery", |t| {
        delivery_path(
            t,
            "mmap Requests \u{2192} Served",
            "mmap Bytes",
            "Cached responses served via memory-mapped file I/O: requests that entered this path \u{2192} requests whose body was fully delivered.",
            metrics::REQUESTS_MMAP.get(),
            metrics::SERVED_MMAP.get(),
            metrics::BYTES_SERVED_MMAP.get(),
        );
        delivery_path(
            t,
            "sendfile Requests \u{2192} Served",
            "sendfile Bytes",
            "Cached responses served via Linux sendfile(2) zero-copy: requests that entered this path \u{2192} requests whose body was fully delivered.",
            metrics::REQUESTS_SENDFILE.get(),
            metrics::SERVED_SENDFILE.get(),
            metrics::BYTES_SERVED_SENDFILE.get(),
        );
        delivery_path(
            t,
            "splice Requests \u{2192} Served",
            "splice Bytes",
            "Responses streamed from upstream to client via Linux splice(2) zero-copy (small userspace-written tails such as header prefixes and kTLS handshake spill included).",
            metrics::REQUESTS_SPLICE.get(),
            metrics::SERVED_SPLICE.get(),
            metrics::BYTES_SERVED_SPLICE.get(),
        );
        delivery_path(
            t,
            "copy Requests \u{2192} Served",
            "copy Bytes",
            "Cached responses served via plain userspace read/write copy.",
            metrics::REQUESTS_COPY.get(),
            metrics::SERVED_COPY.get(),
            metrics::BYTES_SERVED_COPY.get(),
        );
        delivery_path(
            t,
            "channel Requests \u{2192} Served",
            "channel Bytes",
            "Late-joiner responses streamed via the hyper ChannelBody path while an upstream download is still in flight.",
            metrics::REQUESTS_CHANNEL.get(),
            metrics::SERVED_CHANNEL.get(),
            metrics::BYTES_SERVED_CHANNEL.get(),
        );
        delivery_path(
            t,
            "passthrough Requests \u{2192} Served",
            "passthrough Bytes",
            "Uncached responses proxied through to clients without storing anything on disk.",
            metrics::REQUESTS_PASSTHROUGH.get(),
            metrics::SERVED_PASSTHROUGH.get(),
            metrics::BYTES_SERVED_PASSTHROUGH.get(),
        );
        t.row_tip(
            "Clients Demoted (splice \u{2192} file-serve)",
            "Splice clients demoted to ordinary cached-file delivery, e.g. because they joined an in-progress download.",
            metrics::CLIENTS_DEMOTED.get(),
        );
        t.row_tip(
            "Late Joiners (coalesced)",
            "Clients that joined an already in-progress download and shared its data.",
            metrics::LATE_JOINERS_TOTAL.get(),
        );
        t.row_tip(
            "Late Joiner Peak per Download",
            "Peak number of concurrent late joiners observed on a single download.",
            metrics::LATE_JOINER_PEAK_PER_DOWNLOAD.get(),
        );
    });
}

fn build_upstream_group(g: &mut Groups) {
    let status_2xx = metrics::UPSTREAM_STATUS_2XX.get();
    let status_3xx = metrics::UPSTREAM_STATUS_3XX.get();
    let status_200 = metrics::UPSTREAM_STATUS_200.get();
    let status_301 = metrics::UPSTREAM_STATUS_301.get();
    let status_302 = metrics::UPSTREAM_STATUS_302.get();
    let status_304 = metrics::UPSTREAM_STATUS_304.get();
    let status_307 = metrics::UPSTREAM_STATUS_307.get();
    let status_308 = metrics::UPSTREAM_STATUS_308.get();

    let pool_new = metrics::POOL_NEW.get();
    let miss_empty = metrics::POOL_MISS_EMPTY.get();
    let miss_dead = metrics::POOL_MISS_DEAD.get();
    let miss_failed = metrics::POOL_MISS_FAILED.get();
    let miss_no_scheme = metrics::POOL_MISS_NO_SCHEME.get();

    let upgrade_attempted = metrics::HTTPS_UPGRADE_ATTEMPTED.get();
    let upgrade_succeeded = metrics::HTTPS_UPGRADE_SUCCEEDED.get();
    let upgrade_reverted = metrics::HTTPS_UPGRADE_REVERTED.get();
    let upgrade_failed = metrics::HTTPS_UPGRADE_FAILED.get();

    g.group("Upstream", |t| {
        t.row_tip(
            "Bytes Downloaded",
            "Total bytes fetched from upstream mirrors.",
            HumanFmt::Size(metrics::BYTES_DOWNLOADED_UPSTREAM.get()),
        );
        t.row_tip(
            "2xx",
            "Successful responses received from upstream mirrors. Warns when the class total does not match the 200 counter below it.",
            warn_if(status_2xx, status_2xx != status_200),
        );
        t.row_tip(
            "3xx",
            "Redirect and not-modified responses from upstream. Warns when the class total does not match the individual 3xx counters below it.",
            warn_if(
                status_3xx,
                status_3xx != status_301 + status_302 + status_304 + status_307 + status_308,
            ),
        );
        t.row_tip(
            "4xx",
            "Client-error responses received from upstream mirrors.",
            metrics::UPSTREAM_STATUS_4XX.get(),
        );
        t.row_tip(
            "5xx",
            "Server-error responses received from upstream mirrors.",
            WarnNonzero(metrics::UPSTREAM_STATUS_5XX.get()),
        );
        t.row_tip(
            "Other",
            "Upstream responses outside the 2xx-5xx classes.",
            WarnNonzero(metrics::UPSTREAM_STATUS_OTHER.get()),
        );
        t.row("200 OK", status_200);
        t.row("301 Moved Permanently", status_301);
        t.row("302 Found", status_302);
        t.row("304 Not Modified", status_304);
        t.row("307 Temporary Redirect", status_307);
        t.row("308 Permanent Redirect", status_308);
        t.row_tip(
            "Retries",
            "Upstream requests retried after a transient failure.",
            metrics::UPSTREAM_RETRIES.get(),
        );
        t.row_tip(
            "Connect Failures (splice, TCP)",
            "Splice-path upstream TCP setup failures.",
            WarnNonzero(metrics::UPSTREAM_CONNECT_FAILED.get()),
        );
        t.row_tip(
            "Connect Failures (splice, TLS)",
            "Splice-path upstream TLS handshake failures.",
            WarnNonzero(metrics::UPSTREAM_TLS_FAILED.get()),
        );
        t.row_tip(
            "Timeouts (connect)",
            "Configured-timeout firings while connecting to an upstream mirror.",
            metrics::HTTP_TIMEOUT_UPSTREAM_CONNECT.get(),
        );
        t.row_tip(
            "Timeouts (read)",
            "Configured-timeout firings while reading upstream header or body bytes.",
            metrics::HTTP_TIMEOUT_UPSTREAM_READ.get(),
        );
        t.row_tip(
            "Download Cap Transitions",
            "Concurrent-upstream-download cap state transitions.",
            metrics::UPSTREAM_DOWNLOAD_CAP_TRANSITIONS.get(),
        );
        t.row_tip(
            "Downloads Rejected (cap)",
            "Downloads refused because the concurrent-upstream-download cap was reached.",
            metrics::UPSTREAM_DOWNLOAD_REJECTED_CAP.get(),
        );
        t.row_tip(
            "Downloads Aborted",
            "Active upstream downloads aborted before completion.",
            metrics::DOWNLOADS_ABORTED.get(),
        );
        t.row_tip(
            "Rate-Limit Cancellations (upstream)",
            "Transfers cancelled because the configured minimum download rate was not met on the upstream side.",
            metrics::RATE_LIMIT_UPSTREAM.get(),
        );
        t.row_tip(
            "Rate-Limit Cancellations (client)",
            "Transfers cancelled because the configured minimum download rate was not met on the client side.",
            metrics::RATE_LIMIT_CLIENT.get(),
        );
        t.row_tip(
            "Pool Reused",
            "Upstream requests served from an already-open pooled connection.",
            metrics::POOL_REUSED.get(),
        );
        t.row_tip(
            "Pool New",
            "Newly opened upstream connections. Warns unless the four miss counters below it sum to this value: every new connection falls through from exactly one miss arm.",
            warn_if(
                pool_new,
                pool_new != miss_empty + miss_dead + miss_failed + miss_no_scheme,
            ),
        );
        t.row_tip("Pool Miss (empty)", "No pooled connection was available.", miss_empty);
        t.row_tip(
            "Pool Miss (dead)",
            "The pooled connection had been closed by the peer.",
            miss_dead,
        );
        t.row_tip(
            "Pool Miss (failed)",
            "The in-flight request on a pooled connection errored.",
            miss_failed,
        );
        t.row_tip(
            "Pool Miss (no scheme)",
            "No cached scheme for the host, so the pool was bypassed.",
            miss_no_scheme,
        );
        t.row_tip(
            "Pool Return-Evicted",
            "Connections evicted at the point they were returned to the pool.",
            metrics::POOL_RETURN_EVICTED.get(),
        );
        t.row_tip(
            "HTTPS Upgrade Attempted",
            "Plain-HTTP requests the daemon tried to upgrade to HTTPS. Warns unless the three outcome counters below it sum to this value.",
            warn_if(
                upgrade_attempted,
                upgrade_attempted != upgrade_succeeded + upgrade_reverted + upgrade_failed,
            ),
        );
        t.row_tip(
            "HTTPS Upgrade Succeeded",
            "Upgrade attempts that completed over HTTPS.",
            upgrade_succeeded,
        );
        t.row_tip(
            "HTTPS Upgrade Reverted",
            "Auto-mode soft give-ups that fell back to plain HTTP.",
            upgrade_reverted,
        );
        t.row_tip(
            "HTTPS Upgrade Failed",
            "Terminal upgrade failures: Always-mode exhaustion, or a non-connect transport error in any mode.",
            upgrade_failed,
        );
        t.row_tip(
            "Scheme-Cache Removals",
            "Entries dropped from the per-host scheme cache.",
            metrics::SCHEME_CACHE_REMOVED.get(),
        );
        t.row_tip(
            "Protocol Violations",
            "Mirror responses that broke the HTTP contract: body over- or under-ran the announced Content-Length, missing or mismatched Content-Range, missing Content-Length on a non-volatile fetch, or 206 returned without a Range request.",
            WarnNonzero(metrics::UPSTREAM_PROTOCOL_VIOLATION.get()),
        );
        t.row_tip(
            "Unsolicited 206",
            "Mirror responses that returned 206 Partial Content for a request the proxy issued without a Range header. Rejected with 502 to avoid cache poisoning. A telemetry slice of Protocol Violations.",
            WarnNonzero(metrics::UPSTREAM_UNSOLICITED_206.get()),
        );
        t.row_tip(
            "hyper Failures (pre-response)",
            "Hyper-backend connect, TLS and request-framing failures, aggregated. Splice-path equivalents are reported separately.",
            WarnNonzero(metrics::UPSTREAM_HYPER_REQUEST_FAILED.get()),
        );
        t.row_tip(
            "hyper Failures (body)",
            "Hyper-backend post-response body-stream errors.",
            WarnNonzero(metrics::UPSTREAM_HYPER_BODY_ERR.get()),
        );
        t.row_tip(
            "kTLS RX Enabled",
            "Connections where kernel-TLS receive offload was enabled and successfully started splicing application data.",
            metrics::KTLS_RX_ENABLED.get(),
        );
        t.row_tip(
            "kTLS Fallbacks (permanent)",
            "kTLS fallbacks that block the host from further kTLS retries until the cooldown expires.",
            AlertNonzero(metrics::KTLS_FALLBACK_PERMANENT.get()),
        );
        t.row_tip(
            "kTLS Fallbacks (transient)",
            "Post-`setup_rx` drain races; the host is not blocked.",
            WarnNonzero(metrics::KTLS_FALLBACK_TRANSIENT.get()),
        );
    });
}

fn build_tunnels_group(g: &mut Groups) {
    g.group("HTTPS Tunnels", |t| {
        t.row_tip(
            "Connects (total)",
            "HTTPS-tunnel CONNECT requests accepted since the daemon started.",
            metrics::TUNNEL_CONNECTS_TOTAL.get(),
        );
        t.row_tip("Connects (active)", "Tunnels currently open.", active_tunnels());
        t.row_tip(
            "Connects (peak)",
            "Peak concurrent tunnels observed since startup.",
            metrics::CONNECT_TUNNEL_ACTIVE_PEAK.get(),
        );
        t.row_tip(
            "Bytes (client \u{2192} upstream)",
            "Bytes copied client-to-upstream through completed tunnels. Only counted when the tunnel exits cleanly.",
            HumanFmt::Size(metrics::BYTES_TUNNELED_CLIENT_TO_UPSTREAM.get()),
        );
        t.row_tip(
            "Bytes (upstream \u{2192} client)",
            "Bytes copied upstream-to-client through completed tunnels. Only counted when the tunnel exits cleanly.",
            HumanFmt::Size(metrics::BYTES_TUNNELED_UPSTREAM_TO_CLIENT.get()),
        );
        t.row_tip(
            "Rejected (policy)",
            "CONNECT requests refused by the configured tunnel policy.",
            metrics::TUNNEL_REJECTED_POLICY.get(),
        );
        t.row_tip(
            "Rejected (capacity)",
            "CONNECT requests refused because the tunnel capacity limit was reached.",
            metrics::TUNNEL_REJECTED_CAPACITY.get(),
        );
        t.row_tip(
            "Transfer Failures",
            "Post-acceptance tunnel failures: HTTP upgrade failure, upstream connect failure or timeout, or mid-transfer error. Counts tunnels that were accepted but did not complete cleanly.",
            WarnNonzero(metrics::TUNNEL_TRANSFER_FAILED.get()),
        );
        t.row_tip(
            "Closed (idle)",
            "Established tunnels torn down after `client_idle_timeout` without a byte in either direction. Informational: idle sockets reclaimed, not failures.",
            metrics::TUNNEL_IDLE_CLOSED.get(),
        );
    });
}

fn build_cleanup_group(g: &mut Groups) {
    g.group("Cleanup", |t| {
        t.row_tip(
            "Evictions (total)",
            "Cache files removed by the background cleanup across all runs since the daemon started.",
            metrics::CLEANUP_EVICTIONS.get(),
        );
        t.row_tip(
            "Bytes Reclaimed (total)",
            "Disk space reclaimed by the background cleanup across all runs since the daemon started.",
            HumanFmt::Size(metrics::CLEANUP_BYTES_RECLAIMED.get()),
        );
        t.row_tip(
            "By-Hash Unreferenced (total)",
            "By-hash index files reclaimed because their digest was absent from the mirror's current Release set (a subset of total evictions). The rest age out via `byhash_retention_days` when no current Release can be read.",
            metrics::CLEANUP_BYHASH_UNREFERENCED.get(),
        );
        t.row_tip(
            "Checksum Mismatches",
            "Cache files removed because their content hash did not match the SHA256/SHA512 advertised in the upstream Packages stanza. Non-zero indicates corruption or a mirror inconsistency.",
            AlertNonzero(metrics::CLEANUP_CHECKSUM_MISMATCHES.get()),
        );
        t.row_tip(
            "Checksum Skips",
            "Digest verifications skipped because the file was already verified in an earlier cleanup cycle and is unchanged (same inode, size and expected digest).",
            metrics::CLEANUP_CHECKSUM_SKIPS.get(),
        );
        t.row_tip(
            "Last Run Duration",
            "Wall-clock time the most recent cleanup run took.",
            format_args!("{}s", metrics::LAST_CLEANUP_DURATION_SECS.get()),
        );
        t.row_tip(
            "Last Run Files Removed",
            "Cache files removed by the most recent cleanup run.",
            metrics::LAST_CLEANUP_FILES_REMOVED.get(),
        );
        t.row_tip(
            "Last Run Bytes Reclaimed",
            "Disk space reclaimed by the most recent cleanup run.",
            HumanFmt::Size(metrics::LAST_CLEANUP_BYTES_RECLAIMED.get()),
        );
    });
}

fn build_database_group(g: &mut Groups) {
    let database_tx = DB_TASK_QUEUE_SENDER
        .get()
        .expect("Sender initialized in main_loop()");
    let channel_max = database_tx.max_capacity();
    let in_flight = channel_max.saturating_sub(database_tx.capacity());

    let depth_class = RatioClass::new(in_flight as u64, channel_max as u64);
    let peak = metrics::DB_QUEUE_DEPTH_PEAK.get();
    let peak_class = RatioClass::new(peak, channel_max as u64);

    g.group("Database", |t| {
        t.row_tip(
            "Queue Depth (current / max)",
            "Commands queued for the database task against the channel's capacity. A depth that sits near the cap means the writer is the bottleneck.",
            format_args!(
                "{} / {channel_max}",
                Colorize {
                    inner: in_flight,
                    class: depth_class,
                },
            ),
        );
        t.row_tip(
            "Queue Depth Peak",
            "Highest queue depth observed since the daemon started.",
            Colorize {
                inner: peak,
                class: peak_class,
            },
        );
        t.row_tip(
            "Commands Sent",
            "Commands handed to the database task since the daemon started.",
            metrics::DB_COMMANDS_SENT.get(),
        );
        t.row_tip(
            "Queue Full-Waits",
            "Times a producer had to wait because the command channel was full.",
            WarnNonzero(metrics::DB_QUEUE_FULL_WAITS.get()),
        );
        t.row_tip(
            "Queue Full-Transitions",
            "Times the command channel went from having room to being full.",
            WarnNonzero(metrics::DB_QUEUE_FULL_TRANSITIONS.get()),
        );
        t.row_tip(
            "Commands Dropped (shutdown)",
            "Queued commands discarded because the daemon was shutting down.",
            WarnNonzero(metrics::DB_COMMANDS_DROPPED_SHUTDOWN.get()),
        );
        t.row_tip(
            "Batch Flushes (by size)",
            "Batches flushed because they reached the size threshold. Under load this should dominate the by-time counter.",
            metrics::DB_BATCH_FLUSHES_BY_SIZE.get(),
        );
        t.row_tip(
            "Batch Flushes (by time)",
            "Batches flushed because the timer expired. Idle periods favour this over the by-size counter.",
            metrics::DB_BATCH_FLUSHES_BY_TIME.get(),
        );
        t.row_tip(
            "Batch Flushes (on shutdown)",
            "Batches flushed as part of the shutdown drain.",
            metrics::DB_BATCH_FLUSHES_ON_SHUTDOWN.get(),
        );
        t.row_tip(
            "Peak Batch Size",
            "Most commands ever coalesced into a single flush.",
            metrics::DB_BATCH_SIZE_PEAK.get(),
        );
        t.row_tip(
            "Mirror Cache Entries",
            "Process-local mirror-id cache: hydrated at startup, grows on each newly observed mirror, never evicted.",
            metrics::DB_MIRROR_CACHE_ENTRIES.get(),
        );
        t.row_tip(
            "Mirror Cache Hits",
            "Mirror-id lookups served from the process-local cache.",
            metrics::DB_MIRROR_CACHE_HITS.get(),
        );
        t.row_tip(
            "Mirror Cache Misses",
            "Mirror-id lookups that had to reach the database.",
            metrics::DB_MIRROR_CACHE_MISSES.get(),
        );
        t.row_tip(
            "last_seen Rows Flushed",
            "Cumulative `mirrors_v2.last_seen` rows the periodic task has written back to disk.",
            metrics::DB_MIRROR_LAST_SEEN_FLUSHED.get(),
        );
        t.row_tip(
            "Operation Failures",
            "SQLite operations that failed.",
            AlertNonzero(metrics::DB_OPERATION_FAILED.get()),
        );
    });
}

fn build_errors_group(g: &mut Groups) {
    g.group("Storage Errors", |t| {
        t.row_tip(
            "Cache I/O Failures",
            "Cached-file syscall failures (write/flush/read/rename/create/stat/open/mmap/seek) on serving, download, scan and cleanup paths, regardless of whether a client response was affected.",
            AlertNonzero(metrics::CACHE_IO_FAILURE.get()),
        );
        t.row_tip(
            "Non-Regular Files",
            "Cache entries observed as non-regular non-directory files (FIFO, socket, device, symlink); also bumped for stray directories on some serving/sweep paths. Serving paths then return 5xx, download paths abort, the startup scan and this dashboard leave the entry in place, and cleanup unlinks it.",
            AlertNonzero(metrics::CACHE_NON_REGULAR.get()),
        );
        t.row_tip(
            "Unexpected Directories",
            "Cache entries observed as directories where the cache layout does not allow one (an unknown host at the cache root, a non-layout directory in a mirror, anything in a pool or by-hash leaf). Cleanup leaves the directory in place and emits a warn; the tmp/ subtree is the sole exception where the directory is recursively removed once aged. Usually needs an operator to investigate.",
            WarnNonzero(metrics::CACHE_DIRECTORY_UNEXPECTED.get()),
        );
        t.row_tip(
            "Unexpected Regular Files",
            "Cache entries observed as regular files where the cache layout does not allow one (the cache root, a non-deb file directly in a mirror directory, a non-UTF-8-named file cleanup cannot match). The file is left in place with a warn; typically an operator artefact rather than a tampering signal.",
            WarnNonzero(metrics::CACHE_UNEXPECTED_REGULAR.get()),
        );
        t.row_tip(
            "Logstore Evictions",
            "Important-log ring-buffer evictions due to overflow.",
            WarnNonzero(metrics::LOGSTORE_EVICTIONS.get()),
        );
    });
}
