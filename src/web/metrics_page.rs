//! The collapsed Metrics section of the dashboard: every counter in
//! `metrics.rs` except the limiter gauges and their peaks, time-at-cap
//! clocks, admission counters and `LOGSTORE_EVICTIONS` (the Capacity
//! section, `dashboard.rs`), `ACTIVE_CLIENT_DOWNLOADS_PEAK` (Daemon Status)
//! and `CACHE_QUOTA_UTIL_PEAK_BPS` (the disk-usage cell), split into titled
//! subsections with the alert/warn policy applied per row.
//!
//! Every row should send the operator somewhere: to a config option (the
//! tooltip names it), to a client (the Clients table) or to a mirror (the
//! Mirrors table). Rules that keep a list of ~150 counters, nearly all zero
//! on a healthy daemon, readable:
//!
//! - one number per cell. A label that has to enumerate its value's
//!   positions (`(current / max, peak, sent, full-waits, ...)`) is a legend,
//!   and a legend means the cell is really several cells. Genuine ratios
//!   (`hits / misses`, `requests -> served`) stay together, because there the
//!   pairing is the metric.
//! - every counter belongs to exactly one [`Groups::group`], and the rows an
//!   operator reads together share it: download admission, client delivery
//!   health, passthrough. Adding a counter means choosing its subsection.
//! - a part is nested under its total ([`Entry::parts`]): status codes under
//!   their class, abort causes under the abort count.
//! - highlighting marks a bad sign (a [`metrics::Signal`]): warn when the
//!   operator should look, alert when something is broken. A count that is
//!   non-zero on every healthy daemon is not highlighted, or it trains the
//!   reader to ignore the colour.
//! - a row that cannot move in this build or configuration is not shown
//!   ([`Shown`]): a feature compiled out, HTTPS upgrades off, tunnels off.
//!
//! [`Entry::parts`]: super::table::Entry::parts

use std::fmt::{self, Display, Formatter};

use crate::{
    config::HttpsUpgradeMode,
    global_checksum_registry, global_config, global_verify_throttle,
    humanfmt::HumanFmt,
    metrics::{self, Counter},
    swrite,
    uncacheables::UNCACHEABLES_MAX,
};

use super::{
    fmt::{Level, Nonzero, alert_if, warn_if},
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

/// Backends compiled into this build. A counter only a compiled-out backend
/// bumps reads 0 forever; its row is not shown.
///
/// The splice backend: its delivery path, upstream pool, pipe resizes and
/// client demotion.
const SPLICE: bool = cfg!(feature = "splice");
/// The hyper backend: the copy and channel delivery paths, its body-stream
/// errors and unhandled-header discovery.
const HYPER: bool = cfg!(feature = "hyper");
/// The sendfile backend: its delivery path and its own header-read loop (the
/// only reader of the request-read and header-timeout counters).
const SENDFILE: bool = cfg!(feature = "sendfile");

/// Which rows can move in this configuration (the build is [`SPLICE`],
/// [`HYPER`] and [`SENDFILE`]). A counter only a disabled feature reaches
/// reads 0 forever; showing it suggests a check the operator cannot act on.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Shown {
    /// `https_upgrade_mode` other than `Never`.
    https_upgrade: bool,
    /// `https_tunnel_enabled`.
    tunnels: bool,
}

impl Shown {
    fn new(https_upgrade_mode: HttpsUpgradeMode, https_tunnel_enabled: bool) -> Self {
        Self {
            https_upgrade: https_upgrade_mode != HttpsUpgradeMode::Never,
            tunnels: https_tunnel_enabled,
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
            // The full metrics section is comfortably past 40 KB of markup.
            out: String::with_capacity(64 * 1024),
        }
    }

    fn group(&mut self, title: &'static str, build: impl FnOnce(&mut DetailsList)) {
        let mut list = DetailsList::new();
        build(&mut list);
        swrite!(
            self.out,
            "<h3 class=\"group\">{title}</h3>{}",
            list.finish()
        );
    }

    fn finish(self) -> String {
        self.out
    }
}

/// A request-to-served funnel, `requests -> served (pct)`, alerting on the
/// impossible direction.
#[derive(Clone, Copy)]
struct Funnel {
    requests: u64,
    served: u64,
}
impl Funnel {
    /// Served first: its request is counted before it, so this order cannot
    /// read more served than started.
    fn load(requests: &Counter, served: &Counter) -> Self {
        let served = served.get();
        Self {
            requests: requests.get(),
            served,
        }
    }
}
impl Display for Funnel {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let Self { requests, served } = *self;
        write!(
            f,
            "{requests} \u{2192} {}{}",
            alert_if(served, served > requests),
            OptPctSuffix {
                num: served,
                total: requests,
            },
        )
    }
}

/// The two cells a delivery path contributes: its request-to-served funnel
/// and the bytes it moved.
fn delivery_path(
    t: &mut DetailsList,
    labels: [&'static str; 2],
    tips: [&'static str; 2],
    counters: [&Counter; 2],
    bytes: u64,
) {
    let [requests_label, bytes_label] = labels;
    let [requests_tip, bytes_tip] = tips;
    let [requests, served] = counters;
    t.row_tip(requests_label, requests_tip, Funnel::load(requests, served));
    t.row_tip(bytes_label, bytes_tip, HumanFmt::Size(bytes));
}

pub(super) fn build_metrics_html() -> String {
    let config = global_config();
    let shown = Shown::new(config.https_upgrade_mode, config.https_tunnel_enabled);
    let mut g = Groups::new();

    build_requests_group(&mut g);
    build_connections_group(&mut g);
    build_refusals_group(&mut g, shown);
    build_admission_group(&mut g);
    build_client_delivery_group(&mut g);
    build_delivery_group(&mut g);
    build_passthrough_group(&mut g);
    build_cache_group(&mut g);
    build_integrity_group(&mut g);
    build_upstream_group(&mut g);
    if shown.https_upgrade {
        build_https_upgrade_group(&mut g);
    }
    if SPLICE {
        build_pool_group(&mut g);
    }
    if shown.tunnels {
        build_tunnels_group(&mut g);
    }
    build_cleanup_group(&mut g);
    build_database_group(&mut g);
    build_errors_group(&mut g);

    g.finish()
}

fn build_requests_group(g: &mut Groups) {
    // Every subset is loaded before the total it is compared against: the
    // total is bumped first, so this order can only under-read the subset
    // and a comparison cannot flash a warning for one refresh.
    let all = Funnel::load(&metrics::REQUESTS_TOTAL, &metrics::SERVED_TOTAL);
    let webui = Funnel::load(&metrics::WEBUI_REQUESTS, &metrics::SERVED_WEBUI);

    let status_200 = metrics::CLIENT_STATUS_200.get();
    let status_206 = metrics::CLIENT_STATUS_206.get();
    let status_2xx = metrics::CLIENT_STATUS_2XX.get();
    let status_304 = metrics::CLIENT_STATUS_304.get();
    let status_3xx = metrics::CLIENT_STATUS_3XX.get();

    g.group("Requests", |t| {
        t.row_tip(
            "Requests \u{2192} Served",
            "Total HTTP requests handled \u{2192} requests whose response body was fully delivered to the client.",
            all,
        );
        t.row_tip(
            "Web UI Requests \u{2192} Served",
            "The same split for the local web interface.",
            webui,
        );
        t.entry("Client 2xx")
            .tip("Successful responses returned to clients. A relayed 203 or 204 counts here without a code row of its own, so the class may exceed 200 + 206; it warns only if the code rows exceed the class, which is a counting bug.")
            .parts(|p| {
                p.row("Client 200 OK", status_200);
                p.row("Client 206 Partial Content", status_206);
            })
            .value(warn_if(status_2xx, status_200 + status_206 > status_2xx));
        t.entry("Client 3xx")
            .tip("Redirect and not-modified responses returned to clients. A relayed upstream redirect counts here without a code row of its own, so the class may exceed 304; it warns only if 304 exceeds the class, which is a counting bug.")
            .parts(|p| p.row("Client 304 Not Modified", status_304))
            .value(warn_if(status_3xx, status_304 > status_3xx));
        t.entry("Client 4xx")
            .tip("Client-error responses. Not highlighted: pdiff rejections, missing packages relayed from a mirror and web-interface 404 probes land here routinely.")
            .parts(|p| {
                p.row("Client 410 Gone", metrics::CLIENT_STATUS_410.get());
                p.row(
                    "Client 416 Range Not Satisfiable",
                    metrics::CLIENT_STATUS_416.get(),
                );
            })
            .value(metrics::CLIENT_STATUS_4XX.get());
        t.entry("Client 5xx")
            .tip("Server-error responses returned to clients, relayed upstream errors included. A mix of causes with different remedies, so the class only warns; the code rows say which one moved.")
            .parts(|p| {
                p.signal(
                    "Client 500 Internal Server Error",
                    "The proxy itself failed: a cache read or write broke (Cache Access Failure) or a download aborted for an internal reason. See Storage Errors and the log.",
                    Level::Alert,
                    &metrics::CLIENT_STATUS_500,
                );
                p.signal(
                    "Client 502 Bad Gateway",
                    "An upstream fetch failed or its answer was refused (Upstream Error), or the mirror itself answered 502. The Mirrors table names the mirror.",
                    Level::Warn,
                    &metrics::CLIENT_STATUS_502,
                );
                p.signal(
                    "Client 503 Service Unavailable",
                    "A deliberate refusal: disk_quota or min_disk_free, max_upstream_downloads, max_passthrough_relays or the checksum verify throttle (Download Admission says which); or the mirror itself answered 503.",
                    Level::Warn,
                    &metrics::CLIENT_STATUS_503,
                );
            })
            .signal(Level::Warn, &metrics::CLIENT_STATUS_5XX);
        t.signal(
            "Client Other",
            "Responses outside the 2xx-5xx classes.",
            Level::Warn,
            &metrics::CLIENT_STATUS_OTHER,
        );
        if SENDFILE {
            t.row_tip(
                "Read Failures (peer disconnect)",
                "Request-header reads the client reset or closed in the middle of a header. A clean close between keep-alive requests is not counted. Not highlighted: flaky client links.",
                metrics::REQUEST_READ_PEER_DISCONNECT.get(),
            );
            t.signal(
                "Read Failures (protocol error)",
                "Request-header reads that failed on oversized or malformed headers: a broken or abusive client (the log names it).",
                Level::Warn,
                &metrics::REQUEST_READ_PROTOCOL_ERROR,
            );
            t.row_tip(
                "Timeouts (client header read)",
                "Clients that sent no complete request header within client_idle_timeout (slow-loris shaped, or idle between keep-alive requests). Not highlighted: idle keep-alive connections end this way.",
                metrics::HTTP_TIMEOUT_CLIENT_HEADER.get(),
            );
        }
        if HYPER {
            t.row_tip(
                "Unhandled Request Headers",
                "HTTP request headers outside the daemon's known set, counted per header, on requests that start a download in the hyper backend. A developer's discovery signal, not an operator alarm; the log names the header.",
                metrics::UNHANDLED_REQUEST_HEADERS.get(),
            );
        }
    });
}

fn build_connections_group(g: &mut Groups) {
    let connections_accepted = metrics::CONNECTIONS_ACCEPTED.get();
    let requests_total = metrics::REQUESTS_TOTAL.get();
    g.group("Connections", |t| {
        t.row_tip(
            "Connections Accepted",
            "TCP connections accepted from clients since the daemon started, refused ones included, and the requests-per-connection ratio.",
            format_args!(
                "{connections_accepted}{}",
                OptReqPerConn {
                    requests: requests_total,
                    connections: connections_accepted,
                },
            ),
        );
        t.signal(
            "Connections Rejected (global cap)",
            "Connections closed at accept time because max_connections was reached: a flood, or a cap below the real client population. Raise max_connections and LimitNOFILE together; the Capacity section shows how close the connections run to it.",
            Level::Warn,
            &metrics::CONNECTION_REJECTED_GLOBAL_CAP,
        );
        t.signal(
            "Connections Rejected (per-IP cap)",
            "Connections closed at accept time because their source IP already held max_connections_per_client_ip (128 by default, 0 disables it): a noisy client, or many clients behind one NAT address. The Clients table names the IP.",
            Level::Warn,
            &metrics::CONNECTION_REJECTED_PER_IP_CAP,
        );
        t.signal(
            "Connections Rejected (client ACL)",
            "Connections closed at accept time because the source address is outside both allowed_proxy_clients and allowed_webif_clients. The Clients table names the IP.",
            Level::Warn,
            &metrics::CONNECTION_REJECTED_ACL,
        );
        t.signal(
            "Accept Failures (retried)",
            "accept(2) failures retried after a short pause instead of stopping the daemon: descriptor exhaustion (EMFILE/ENFILE), ENOBUFS/ENOMEM, ECONNABORTED. The process is at its file-descriptor budget: raise LimitNOFILE, or lower max_connections below it.",
            Level::Warn,
            &metrics::ACCEPT_TRANSIENT_FAILURES,
        );
    });
}

fn build_refusals_group(g: &mut Groups, shown: Shown) {
    g.group("Request Refusals", |t| {
        t.row_tip(
            "Rejected (pdiff)",
            "Client requests for pdiff resources, refused because reject_pdiff_requests is set. Not highlighted: apt falls back to the full index.",
            metrics::PDIFF_REJECTED.get(),
        );
        t.signal(
            "Rejected (unsafe path)",
            "Client requests refused with 400 because their path failed the traversal and encoding checks, a percent-decoded cache-name field included (.., %2F, a control byte): a broken or hostile client.",
            Level::Warn,
            &metrics::UNSAFE_PATH_REJECTED,
        );
        t.signal(
            "Proxy Loops Rejected",
            "Requests refused with 508 because their Via already named this proxy: an allowed_mirrors wildcard covers the proxy's own name.",
            Level::Warn,
            &metrics::PROXY_LOOP_REJECTED,
        );
        t.row_tip(
            "Authorization Rejected (mirror)",
            "Requests refused because the requested mirror is outside allowed_mirrors. The Clients table names the client; add the mirror, or fix the client's sources.",
            metrics::AUTHZ_REJECTED_MIRROR.get(),
        );
        t.row_tip(
            "Authorization Rejected (client)",
            "Requests refused because the source address is outside allowed_proxy_clients. The Clients table names the client.",
            metrics::AUTHZ_REJECTED_CLIENT.get(),
        );
        t.row_tip(
            "Authorization Rejected (web interface)",
            "Web-interface requests refused because the source address is outside allowed_webif_clients (falling back to allowed_proxy_clients).",
            metrics::AUTHZ_REJECTED_WEBUI.get(),
        );
        t.signal(
            "Authorization Rejected (web-interface host)",
            "Web-interface requests refused with 421 because their Host names neither an IP address, localhost, the system hostname nor a webif_hostnames entry: a browser reached the dashboard under a rebound DNS name, or an admin uses a name missing from webif_hostnames.",
            Level::Warn,
            &metrics::AUTHZ_REJECTED_WEBUI_HOST,
        );
        if !shown.tunnels {
            // The tunnel group is hidden while tunnels are off, and this is
            // the one tunnel counter that still moves then.
            t.row_tip(
                "CONNECT Refused (tunnels disabled)",
                "CONNECT requests refused because https_tunnel_enabled is off. Enable it (with https_tunnel_allowed_mirrors) if clients need HTTPS repositories through this proxy.",
                metrics::TUNNEL_REJECTED_POLICY.get(),
            );
        }
    });
}

fn build_admission_group(g: &mut Groups) {
    g.group("Download Admission", |t| {
        t.signal(
            "Rejected (quota reached)",
            "Downloads refused with 503 because the cache would exceed disk_quota, or the cache filesystem is down to min_disk_free. Raise either, or free space; cleanup reclaims unreferenced files daily.",
            Level::Warn,
            &metrics::DOWNLOAD_REJECTED_QUOTA,
        );
        t.signal(
            "Rejected (oversize)",
            "Downloads refused because the upstream announced a size above max_object_size.",
            Level::Warn,
            &metrics::DOWNLOAD_REJECTED_OVERSIZE,
        );
        t.signal(
            "Rejected (verify-throttled)",
            "Requests refused with 503 because the resource recently failed checksum verification and is inside its backoff window (verify_checksums_throttle_base, doubling up to verify_checksums_throttle_cap), joiners of a refused download included.",
            Level::Warn,
            &metrics::DOWNLOAD_REJECTED_VERIFY_THROTTLE,
        );
        t.signal(
            "Downloads Rejected (cap)",
            "New downloads refused with 503 because max_upstream_downloads were already in flight (late joiners are exempt). The Capacity section shows how long the cap was hit; raise max_upstream_downloads if it is often.",
            Level::Warn,
            &metrics::UPSTREAM_DOWNLOAD_REJECTED_CAP,
        );
        t.signal(
            "Download Cap Transitions",
            "Times the in-flight downloads reached max_upstream_downloads after having drained to zero: separate saturation episodes, where Downloads Rejected (cap) counts every refusal inside them.",
            Level::Warn,
            &metrics::UPSTREAM_DOWNLOAD_CAP_TRANSITIONS,
        );
        t.entry("Throttled Resources")
            .tip("Resources currently refused with 503 because a recent download failed checksum verification (backoff from verify_checksums_throttle_base up to verify_checksums_throttle_cap; cleared by a verified download). A live count, not a total.")
            .value(Nonzero {
                value: global_verify_throttle().active_len() as u64,
                level: Level::Warn,
            });
        t.row_tip(
            "Downloads Declined",
            "Registered downloads answered without fetching a body, so not aborts: the upstream status was relayed uncached (a 404, say), the answer was refused (oversize, bad framing), or disk_quota, min_disk_free, the checksum verify throttle or max_passthrough_relays refused it. A max_upstream_downloads refusal never registers and counts in Downloads Rejected (cap) instead.",
            metrics::DOWNLOADS_DECLINED.get(),
        );
    });
}

fn build_client_delivery_group(g: &mut Groups) {
    g.group("Client Delivery", |t| {
        t.row_tip(
            "Client Disconnected Mid-Body",
            "Clients that hung up before the response body was complete. Not highlighted: apt closes connections it no longer needs. In the hyper backend any peer disconnect during a request counts. The Clients table names the clients.",
            metrics::CLIENT_DISCONNECTED_MID_BODY.get(),
        );
        t.signal(
            "Timeouts (client body write)",
            "Deliveries aborted because the client accepted no body bytes for http_timeout: a stalled client or a dropped link. The Clients table names the client.",
            Level::Warn,
            &metrics::HTTP_TIMEOUT_CLIENT_BODY,
        );
        t.row_tip(
            "Timeouts (client header write)",
            "Response heads or small proxy-generated responses the client did not accept within http_timeout.",
            metrics::HTTP_TIMEOUT_CLIENT_HEADER_WRITE.get(),
        );
        t.signal(
            "Rate-Limit Cancellations (client)",
            "Deliveries cancelled because the client read below min_download_rate over rate_check_timeframe. The Clients table names the client; lower min_download_rate if the clients are legitimately slow.",
            Level::Warn,
            &metrics::RATE_LIMIT_CLIENT,
        );
        if SPLICE {
            t.row_tip(
                "Clients Demoted (splice \u{2192} file-serve)",
                "Splice deliveries whose client fell below min_download_rate while the upstream kept pace: instead of cancelling, the client was handed to a task serving the growing cache file, so the download itself goes on at the upstream's speed. A climb points at slow clients (the Clients table) or a min_download_rate set too high.",
                metrics::CLIENTS_DEMOTED.get(),
            );
        }
    });
}

fn build_delivery_group(g: &mut Groups) {
    g.group("Delivery Paths", |t| {
        if SENDFILE {
            delivery_path(
                t,
                ["sendfile Requests \u{2192} Served", "sendfile Bytes"],
                [
                    "Cached responses served via Linux sendfile(2) zero-copy by the sendfile backend: requests that entered this path \u{2192} requests whose body was fully delivered.",
                    "Bytes sent via sendfile(2): the sendfile backend's cache hits and late joiners, plus a splice request's demoted tail and resumed prefix (counted as splice requests).",
                ],
                [&metrics::REQUESTS_SENDFILE, &metrics::SERVED_SENDFILE],
                metrics::BYTES_SERVED_SENDFILE.get(),
            );
        }
        if SPLICE {
            delivery_path(
                t,
                ["splice Requests \u{2192} Served", "splice Bytes"],
                [
                    "Responses streamed from upstream to client via Linux splice(2) zero-copy while they are cached.",
                    "Bytes the splice backend delivered, small userspace-written parts (header prefixes, range boundaries, buffered indexes) included.",
                ],
                [&metrics::REQUESTS_SPLICE, &metrics::SERVED_SPLICE],
                metrics::BYTES_SERVED_SPLICE.get(),
            );
        }
        if HYPER {
            delivery_path(
                t,
                ["copy Requests \u{2192} Served", "copy Bytes"],
                [
                    "Cached responses served by the hyper backend via plain userspace read/write copy.",
                    "Bytes of those responses, counted when each body ends.",
                ],
                [&metrics::REQUESTS_COPY, &metrics::SERVED_COPY],
                metrics::BYTES_SERVED_COPY.get(),
            );
            delivery_path(
                t,
                ["channel Requests \u{2192} Served", "channel Bytes"],
                [
                    "Responses streamed by the hyper backend while their upstream download is still in flight: the client that started the download and any late joiners.",
                    "Bytes of those responses, counted when each body ends.",
                ],
                [&metrics::REQUESTS_CHANNEL, &metrics::SERVED_CHANNEL],
                metrics::BYTES_SERVED_CHANNEL.get(),
            );
        }
    });
}

fn build_passthrough_group(g: &mut Groups) {
    g.group("Passthrough", |t| {
        delivery_path(
            t,
            ["passthrough Requests \u{2192} Served", "passthrough Bytes"],
            [
                "Uncached responses relayed to clients without storing anything: unrecognised paths, query strings, and upstream answers that are not cached (a 404, a redirect).",
                "Bytes relayed uncached.",
            ],
            [&metrics::REQUESTS_PASSTHROUGH, &metrics::SERVED_PASSTHROUGH],
            metrics::BYTES_SERVED_PASSTHROUGH.get(),
        );
        t.signal(
            "Passthroughs Rejected (cap)",
            "Uncached passthrough requests refused with 503 because max_passthrough_relays relays were already active. The Capacity section shows how long the cap was hit.",
            Level::Warn,
            &metrics::PASSTHROUGH_REJECTED_CAP,
        );
    });
}

fn build_cache_group(g: &mut Groups) {
    let hits = metrics::CACHE_HITS.get();
    let misses = metrics::CACHE_MISSES.get();
    let lookups = hits + misses;
    let refetched_uptodate = metrics::VOLATILE_REFETCHED_UPTODATE.get();
    let refetched_outofdate = metrics::VOLATILE_REFETCHED_OUTOFDATE.get();
    let refetched = metrics::VOLATILE_REFETCHED.get();

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
        t.entry("Volatile Refetches")
            .tip("Volatile requests (indexes) that found no fresh cached copy and needed upstream, whether they fetched it or joined an in-flight fetch. The two outcomes beneath cover the stale-but-present case only; it warns only if they exceed it, which is a counting bug.")
            .parts(|p| {
                p.row_tip(
                    "Refetch Up-to-Date (304)",
                    "Revalidations where upstream confirmed the cached copy was still current.",
                    refetched_uptodate,
                );
                p.row_tip(
                    "Refetch Out-of-Date (200)",
                    "Revalidations where upstream returned changed content.",
                    refetched_outofdate,
                );
            })
            .value(warn_if(
                refetched,
                refetched < refetched_uptodate + refetched_outofdate,
            ));
        t.row_tip(
            "Late Joiners (coalesced)",
            "Requests that joined an already in-progress download and shared its data instead of fetching again.",
            metrics::LATE_JOINERS_TOTAL.get(),
        );
        t.row_tip(
            "Most Late Joiners on One Download",
            "The most late joiners any single download has had since startup, counting every client that joined it, including those that left before it finished.",
            metrics::LATE_JOINER_PEAK_PER_DOWNLOAD.get(),
        );
        t.row_tip(
            "Partials Still In Use",
            "Downloads that found their .partial still held by an earlier download of the same file and fetched into a scratch file instead of resuming it.",
            metrics::PARTIAL_CLAIM_CONTENDED.get(),
        );
        t.row_tip(
            "Uncacheable Evictions",
            "Recent uncacheable (host, path) entries dropped from the in-memory list the Uncacheables section shows, which keeps a fixed number of the latest. Not highlighted: the list is a sample, not a limit.",
            metrics::UNCACHEABLE
                .get()
                .saturating_sub(UNCACHEABLES_MAX.get() as u64),
        );
        t.signal(
            "Reconcile Events",
            "Cache-size reconciliations that found the in-memory total off from the files on disk and repaired it: something changed the cache behind the daemon's back (an operator, another process) or the accounting has a bug. The log names the delta.",
            Level::Warn,
            &metrics::RECONCILE_EVENTS,
        );
        t.row_tip(
            "Reconcile Bytes Repaired",
            "Total size-accounting error corrected by those reconciliation events.",
            HumanFmt::Size(metrics::RECONCILE_BYTES_REPAIRED.get()),
        );
        t.signal(
            "Size Accounting Corruption",
            "Overflow or underflow detected in the in-memory total-cache-size accounting (value clamped; repaired by the next reconcile): a bug to report.",
            Level::Alert,
            &metrics::CACHE_SIZE_CORRUPTION,
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
        t.signal(
            "Mismatch (rejected)",
            "Downloads rejected because their content did not match the digest their index promised: the mirror serves content its own index disagrees with (the Mirrors table names it). Same event as the checksum cause under Downloads Aborted; cleanup's re-verification counts its own finds under Cleanup, Checksum Mismatches.",
            Level::Alert,
            &metrics::CHECKSUM_MISMATCH,
        );
        t.row_tip(
            "Unverified (no known digest)",
            "Resources for which no expected digest was available in the registry; cached unverified (best-effort).",
            metrics::CHECKSUM_UNVERIFIED.get(),
        );
        t.row_tip(
            "Registry Entries",
            "In-memory checksum-registry entries (expected digests parsed from Packages/Release indices; lost on restart), a live count capped by verify_checksums_max_entries.",
            global_checksum_registry().len(),
        );
        t.row_tip(
            "Re-ingests (touch)",
            "Cached indexes re-ingested because a request answered from cache found their digests missing (restart, eviction, an earlier skip). Climbing on every apt update means verify_checksums_max_entries is below the live working set.",
            metrics::INGEST_TOUCH_TRIGGERED.get(),
        );
        t.signal(
            "Ingests Skipped (queue full)",
            "Index ingests skipped because the ingest line was full; each is retried on the index's next request. Until then downloads of that index's packages go unverified.",
            Level::Warn,
            &metrics::INGEST_SKIPPED_QUEUE_FULL,
        );
        t.signal(
            "Ingests Failed (not retried)",
            "Index files that can never ingest (too large, corrupt, over the decode CPU budget); retried only once the file is replaced. The log names the file.",
            Level::Alert,
            &metrics::INGEST_FAILED_MARKED,
        );
    });
}

fn build_upstream_group(g: &mut Groups) {
    // Subsets before the totals they are compared against (the total is
    // bumped first); see `build_requests_group`.
    let status_200 = metrics::UPSTREAM_STATUS_200.get();
    let status_206 = metrics::UPSTREAM_STATUS_206.get();
    let status_301 = metrics::UPSTREAM_STATUS_301.get();
    let status_302 = metrics::UPSTREAM_STATUS_302.get();
    let status_304 = metrics::UPSTREAM_STATUS_304.get();
    let status_307 = metrics::UPSTREAM_STATUS_307.get();
    let status_308 = metrics::UPSTREAM_STATUS_308.get();
    let status_2xx = metrics::UPSTREAM_STATUS_2XX.get();
    let status_3xx = metrics::UPSTREAM_STATUS_3XX.get();

    // The causes before their total, which is bumped first.
    let abort_causes = [
        (
            "Aborted (upstream failure)",
            "The mirror failed the transfer: connect, head, body, rate or protocol. The Mirrors table names the mirror.",
            Level::Warn,
            &metrics::DOWNLOADS_ABORTED_UPSTREAM,
        ),
        (
            "Aborted (cache I/O failure)",
            "A cache file could not be written, read back or renamed. Check the cache filesystem (space, permissions, errors) and the Storage Errors rows.",
            Level::Alert,
            &metrics::DOWNLOADS_ABORTED_CACHE,
        ),
        (
            "Aborted (checksum mismatch)",
            "The whole body arrived but did not match the digest its index promised, so it was discarded: the mirror serves content its own index disagrees with. Same event as Integrity's Mismatch (rejected).",
            Level::Alert,
            &metrics::DOWNLOADS_ABORTED_CHECKSUM,
        ),
        (
            "Aborted (internal failure)",
            "A transfer broke on this side (a pipe, a task): a bug to report.",
            Level::Alert,
            &metrics::DOWNLOADS_ABORTED_INTERNAL,
        ),
    ]
    .map(|(label, tip, level, signal)| (label, tip, level, signal.get(), signal.last()));
    let cancelled = &metrics::DOWNLOADS_ABORTED_CANCELLED;
    let (cancelled_count, cancelled_last) = (cancelled.get(), cancelled.last());

    g.group("Upstream", |t| {
        t.row_tip(
            "Bytes Downloaded",
            "Total bytes fetched from upstream mirrors.",
            HumanFmt::Size(metrics::BYTES_DOWNLOADED_UPSTREAM.get()),
        );
        t.entry("2xx")
            .tip("Successful responses received from upstream mirrors. Warns only if the 200 and 206 rows exceed it, which is a counting bug; another 2xx code counts here without a row of its own.")
            .parts(|p| {
                p.row("200 OK", status_200);
                p.row_tip(
                    "206 Partial Content",
                    "Answers to a resumed download's Range request.",
                    status_206,
                );
            })
            .value(warn_if(status_2xx, status_200 + status_206 > status_2xx));
        t.entry("3xx")
            .tip("Redirect and not-modified responses from upstream. Warns only if the individual 3xx rows exceed it, which is a counting bug; another 3xx code counts here without a row of its own.")
            .parts(|p| {
                p.row("301 Moved Permanently", status_301);
                p.row("302 Found", status_302);
                p.row("304 Not Modified", status_304);
                p.row("307 Temporary Redirect", status_307);
                p.row("308 Permanent Redirect", status_308);
            })
            .value(warn_if(
                status_3xx,
                status_301 + status_302 + status_304 + status_307 + status_308 > status_3xx,
            ));
        t.row_tip(
            "4xx",
            "Client-error responses received from upstream mirrors. Not highlighted: a package missing from a mirror is a 404.",
            metrics::UPSTREAM_STATUS_4XX.get(),
        );
        t.signal(
            "5xx",
            "Server-error responses received from upstream mirrors. The log names the mirror.",
            Level::Warn,
            &metrics::UPSTREAM_STATUS_5XX,
        );
        t.signal(
            "Other",
            "Upstream responses outside the 2xx-5xx classes.",
            Level::Warn,
            &metrics::UPSTREAM_STATUS_OTHER,
        );
        t.entry("Downloads Aborted")
            .tip("Registered upstream downloads that ended without being cached; the causes beneath split them and sum to this.")
            .parts(|p| {
                for (label, tip, level, value, last) in abort_causes {
                    p.entry(label)
                        .tip(tip)
                        .last(last)
                        .value(Nonzero { value, level });
                }
                p.entry("Aborted (cancelled)")
                    .tip("The download was dropped without a verdict, typically because every client it served went away. No alarm on its own; a climb together with client disconnects points at the clients.")
                    .last(cancelled_last)
                    .value(cancelled_count);
            })
            .signal(Level::Warn, &metrics::DOWNLOADS_ABORTED);
        t.row_tip(
            "Retries",
            "Upstream connect attempts past a request's first: backoff retries after a failed connect, bounded by upstream_retry_budget, and Auto-mode dials of plain HTTP after a failed HTTPS probe. Not highlighted: a retry that connects is the mechanism working.",
            metrics::UPSTREAM_RETRIES.get(),
        );
        t.signal(
            "Connect Failures",
            "Requests whose upstream connect (TCP or TLS) failed for good, after the retries (upstream_retry_budget) and the Auto-mode HTTPS-to-HTTP fallback. Counted once per request. The Mirrors table names the mirror.",
            Level::Warn,
            &metrics::UPSTREAM_CONNECT_FAILED,
        );
        t.signal(
            "Head Failures",
            "Requests whose upstream was connected but whose exchange failed before a response head arrived: reset, EOF, http_timeout or request write. A malformed head counts as a Protocol Violation instead. The Mirrors table names the mirror.",
            Level::Warn,
            &metrics::UPSTREAM_HEAD_FAILED,
        );
        t.signal(
            "Timeouts (connect)",
            "Upstream or CONNECT-tunnel dials that exceeded http_timeout, counted per attempt (a request whose retries all time out counts each).",
            Level::Warn,
            &metrics::HTTP_TIMEOUT_UPSTREAM_CONNECT,
        );
        t.signal(
            "Timeouts (read)",
            "Upstream header or body reads that stalled for http_timeout. The Mirrors table names the mirror.",
            Level::Warn,
            &metrics::HTTP_TIMEOUT_UPSTREAM_READ,
        );
        t.signal(
            "Rate-Limit Cancellations (upstream)",
            "Downloads cancelled because the mirror delivered below min_download_rate over rate_check_timeframe. The Mirrors table names the mirror; lower min_download_rate if the mirror is legitimately slow.",
            Level::Warn,
            &metrics::RATE_LIMIT_UPSTREAM,
        );
        t.entry("Protocol Violations")
            .tip("Mirror responses that broke the HTTP contract: an unparsable or oversized response head, framing that can be read two ways, a body that over- or under-ran its Content-Length, a Content-Length missing on a package or zero on a cached fetch, or a 206 without a Range request. A mirror bug to report; the Mirrors table names it.")
            .parts(|p| {
                p.signal(
                    "Unsolicited 206",
                    "Mirror responses that returned 206 Partial Content for a request the proxy issued without a Range header, rejected with 502 to avoid cache poisoning.",
                    Level::Warn,
                    &metrics::UPSTREAM_UNSOLICITED_206,
                );
            })
            .signal(Level::Warn, &metrics::UPSTREAM_PROTOCOL_VIOLATION);
        t.signal(
            "Body Size Limits",
            "Responses exceeding a local body buffering or relay limit. They may be valid HTTP and do not count as Protocol Violations. A body merely too large to drain for connection reuse is not counted.",
            Level::Warn,
            &metrics::UPSTREAM_BODY_LIMIT,
        );
        if HYPER {
            t.signal(
                "hyper Failures (body)",
                "Hyper-backend upstream errors after the response head arrived, while streaming the body (a reset, a read or TLS failure, a framing error). A body that ended before its announced length counts as a Protocol Violation instead, as in splice.",
                Level::Warn,
                &metrics::UPSTREAM_HYPER_BODY_ERR,
            );
        }
        if SPLICE {
            t.signal(
                "Pipe Resizes Refused (splice)",
                "Plain-HTTP download pipes the kernel refused to grow to 1 MiB (two per download): the service user's pipe quota fs.pipe-user-pages-soft is exhausted, or fs.pipe-max-size is below 1 MiB. Those downloads write the cache every few KiB instead of every MiB; raise the sysctl.",
                Level::Warn,
                &metrics::PIPE_RESIZE_REFUSED,
            );
        }
        t.row_tip(
            "Scheme-Cache Removals",
            "Entries dropped from the per-host scheme cache after the connect-retry budget (upstream_retry_budget) ran out, so the next request probes the scheme again.",
            metrics::SCHEME_CACHE_REMOVED.get(),
        );
    });
}

fn build_https_upgrade_group(g: &mut Groups) {
    // The outcomes before the attempts, which are bumped first.
    let upgrade_succeeded = metrics::HTTPS_UPGRADE_SUCCEEDED.get();
    let upgrade_reverted = metrics::HTTPS_UPGRADE_REVERTED.get();
    let upgrade_failed = metrics::HTTPS_UPGRADE_FAILED.get();
    let upgrade_attempted = metrics::HTTPS_UPGRADE_ATTEMPTED.get();

    g.group("HTTPS Upgrade", |t| {
        t.entry("HTTPS Upgrade Attempted")
            .tip("Plain-HTTP requests the daemon tried to upgrade to HTTPS (https_upgrade_mode). Each resolves to exactly one of the outcomes beneath, which trail it while an upgrade is in flight; it warns only if they exceed it, which is a counting bug.")
            .parts(|p| {
                p.row_tip(
                    "HTTPS Upgrade Succeeded",
                    "Upgrade attempts that completed over HTTPS.",
                    upgrade_succeeded,
                );
                p.row_tip(
                    "HTTPS Upgrade Reverted",
                    "Auto-mode soft give-ups that fell back to plain HTTP. A mirror that keeps reverting has no working HTTPS: list it in http_only_mirrors.",
                    upgrade_reverted,
                );
                p.row_tip(
                    "HTTPS Upgrade Failed",
                    "Terminal upgrade failures: Always-mode exhaustion, or a non-connect transport error in any mode.",
                    upgrade_failed,
                );
            })
            .value(warn_if(
                upgrade_attempted,
                upgrade_succeeded + upgrade_reverted + upgrade_failed > upgrade_attempted,
            ));
    });
}

fn build_pool_group(g: &mut Groups) {
    // A checkout bumps its miss arm *before* `POOL_NEW`, so the
    // new-connection count is the one loaded first.
    let pool_new = metrics::POOL_NEW.get();
    let miss_empty = metrics::POOL_MISS_EMPTY.get();
    let miss_dead = metrics::POOL_MISS_DEAD.get();
    let miss_failed = metrics::POOL_MISS_FAILED.get();
    let miss_no_scheme = metrics::POOL_MISS_NO_SCHEME.get();

    g.group("Upstream Connection Pool", |t| {
        t.row_tip(
            "Pool Reused",
            "Upstream requests served from an already-open pooled connection.",
            metrics::POOL_REUSED.get(),
        );
        t.entry("Pool New")
            .tip("Newly opened upstream connections. Every new connection falls through from exactly one miss arm, but a miss whose connect then fails opens none, so the misses beneath may exceed it; it warns only if it exceeds their sum, which is a counting bug.")
            .parts(|p| {
                p.row_tip(
                    "Pool Miss (empty)",
                    "No pooled connection was available for the host.",
                    miss_empty,
                );
                p.row_tip(
                    "Pool Miss (dead)",
                    "The pooled connection had been closed by the peer.",
                    miss_dead,
                );
                p.row_tip(
                    "Pool Miss (failed)",
                    "The in-flight request on a pooled connection failed and was retried on a fresh one.",
                    miss_failed,
                );
                p.row_tip(
                    "Pool Miss (no scheme)",
                    "No cached scheme for the host, so the pool was bypassed.",
                    miss_no_scheme,
                );
            })
            .value(warn_if(
                pool_new,
                pool_new > miss_empty + miss_dead + miss_failed + miss_no_scheme,
            ));
        t.row_tip(
            "Pool Return-Evicted",
            "Connections evicted at the point they were returned to a full per-host slot.",
            metrics::POOL_RETURN_EVICTED.get(),
        );
    });
}

fn build_tunnels_group(g: &mut Groups) {
    g.group("HTTPS Tunnels", |t| {
        t.row_tip(
            "Connects (total)",
            "HTTPS-tunnel CONNECT requests accepted since the daemon started. The live count and peak are in the Capacity section.",
            metrics::TUNNEL_CONNECTS_TOTAL.get(),
        );
        t.row_tip(
            "Bytes (client \u{2192} upstream)",
            "Bytes copied client-to-upstream through tunnels, however the tunnel ended (cleanly, idle-closed or failed), including bytes pipelined behind the CONNECT request.",
            HumanFmt::Size(metrics::BYTES_TUNNELED_CLIENT_TO_UPSTREAM.get()),
        );
        t.row_tip(
            "Bytes (upstream \u{2192} client)",
            "Bytes copied upstream-to-client through tunnels, however the tunnel ended (cleanly, idle-closed or failed).",
            HumanFmt::Size(metrics::BYTES_TUNNELED_UPSTREAM_TO_CLIENT.get()),
        );
        t.row_tip(
            "Rejected (policy)",
            "CONNECT requests refused because their port is outside https_tunnel_allowed_ports.",
            metrics::TUNNEL_REJECTED_POLICY.get(),
        );
        t.row_tip(
            "Authorization Rejected (tunnel mirror)",
            "CONNECT requests refused because the target is outside https_tunnel_allowed_mirrors. The Clients table names the client.",
            metrics::AUTHZ_REJECTED_TUNNEL_MIRROR.get(),
        );
        t.signal(
            "Rejected (capacity)",
            "CONNECT requests refused with 429 because their source IP already held https_tunnel_max_connections_per_client tunnels (a per-IP cap; there is no global one). The Clients table names the IP.",
            Level::Warn,
            &metrics::TUNNEL_REJECTED_CAPACITY,
        );
        t.signal(
            "Transfer Failures",
            "Accepted tunnels that did not complete cleanly: the client gone before the relay started, an upstream connect failure or timeout, or a mid-transfer error.",
            Level::Warn,
            &metrics::TUNNEL_TRANSFER_FAILED,
        );
        t.row_tip(
            "Closed (idle)",
            "Established tunnels torn down after client_idle_timeout without a byte in either direction. Informational: idle sockets reclaimed, not failures.",
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
            "By-hash index files reclaimed because their digest was absent from the mirror's current Release set (a subset of total evictions). The rest age out via byhash_retention_days when no current Release can be read.",
            metrics::CLEANUP_BYHASH_UNREFERENCED.get(),
        );
        t.signal(
            "Checksum Mismatches",
            "Cached files cleanup removed because their content no longer matched the digest in the mirror's current Packages index: disk corruption, or a mirror that re-issued a file under the same name. The Mirrors table names the mirror; download-time mismatches count under Integrity, Mismatch (rejected).",
            Level::Alert,
            &metrics::CLEANUP_CHECKSUM_MISMATCHES,
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
    g.group("Database", |t| {
        t.row_tip(
            "Commands Sent",
            "Commands handed to the database task since the daemon started. Its queue is a gauge in the Capacity section.",
            metrics::DB_COMMANDS_SENT.get(),
        );
        t.signal(
            "Queue Full-Waits",
            "Sends that found the command channel full: observations of saturation, not waits (an async send may not have to park). Raise db_channel_capacity, or flush sooner with db_batch_flush_max_count / db_batch_flush_interval_secs.",
            Level::Warn,
            &metrics::DB_QUEUE_FULL_WAITS,
        );
        t.signal(
            "Queue Full-Transitions",
            "Separate saturation episodes: times the command channel filled after having drained to empty.",
            Level::Warn,
            &metrics::DB_QUEUE_FULL_TRANSITIONS,
        );
        t.row_tip(
            "Commands Dropped (shutdown)",
            "Commands discarded because the database task had already stopped. Not highlighted: a graceful shutdown drops the tail of the telemetry.",
            metrics::DB_COMMANDS_DROPPED_SHUTDOWN.get(),
        );
        t.row_tip(
            "Batch Flushes (by size)",
            "Batches flushed because they reached db_batch_flush_max_count. Under load this should dominate the by-time counter.",
            metrics::DB_BATCH_FLUSHES_BY_SIZE.get(),
        );
        t.row_tip(
            "Batch Flushes (by time)",
            "Batches flushed because db_batch_flush_interval_secs expired. Idle periods favour this over the by-size counter.",
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
            "Cumulative mirrors_v2.last_seen rows the periodic task has written back to disk.",
            metrics::DB_MIRROR_LAST_SEEN_FLUSHED.get(),
        );
        t.signal(
            "Operation Failures",
            "SQLite operations that failed; the log has the error.",
            Level::Alert,
            &metrics::DB_OPERATION_FAILED,
        );
    });
}

fn build_errors_group(g: &mut Groups) {
    g.group("Storage Errors", |t| {
        t.signal(
            "Cache I/O Failures",
            "Cached-file syscall failures (write/flush/read/rename/create/stat/open/seek) on serving, download, scan and cleanup paths, regardless of whether a client response was affected. The log names the path.",
            Level::Alert,
            &metrics::CACHE_IO_FAILURE,
        );
        t.signal(
            "Non-Regular Files",
            "Cache entries observed as non-regular non-directory files (FIFO, socket, device, symlink); also bumped for stray directories on some serving/sweep paths. Serving paths then return 5xx, download paths abort, the startup scan and this dashboard leave the entry in place, and cleanup unlinks it.",
            Level::Alert,
            &metrics::CACHE_NON_REGULAR,
        );
        t.signal(
            "Unexpected Directories",
            "Cache entries observed as directories where the cache layout does not allow one (an unknown host at the cache root, a non-layout directory in a mirror, anything in a pool or by-hash leaf). Cleanup leaves the directory in place and emits a warn; the tmp/ subtree is the sole exception where the directory is recursively removed once aged.",
            Level::Warn,
            &metrics::CACHE_DIRECTORY_UNEXPECTED,
        );
        t.signal(
            "Unexpected Regular Files",
            "Cache entries observed as regular files where the cache layout does not allow one (the cache root, a non-deb file directly in a mirror directory, a non-UTF-8-named file cleanup cannot match). The file is left in place with a warn; typically an operator artefact rather than a tampering signal.",
            Level::Warn,
            &metrics::CACHE_UNEXPECTED_REGULAR,
        );
    });
}

#[cfg(test)]
mod tests {
    use super::{HttpsUpgradeMode, Shown};

    #[test]
    fn rows_follow_the_build_and_the_config() {
        let shown = Shown::new(HttpsUpgradeMode::Never, false);
        assert!(!shown.https_upgrade);
        assert!(!shown.tunnels);
        for mode in [HttpsUpgradeMode::Auto, HttpsUpgradeMode::Always] {
            let shown = Shown::new(mode, true);
            assert!(shown.https_upgrade, "{mode:?}");
            assert!(shown.tunnels);
        }
    }
}
