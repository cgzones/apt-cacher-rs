//! The collapsed Metrics section of the dashboard: every counter in
//! `metrics.rs` except the limiter gauges and their peaks, time-at-cap
//! clocks, admission counters and `LOGSTORE_EVICTIONS` (the Capacity
//! section, `dashboard.rs`), `ACTIVE_CLIENT_DOWNLOADS_PEAK` (Daemon Status),
//! `ORPHANED_PARTIAL_*` (Cache Statistics) and `CACHE_QUOTA_UTIL_PEAK_BPS`
//! (the disk-usage cell), split into titled
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
    config::{Config, HttpsUpgradeMode},
    global_checksum_registry, global_config, global_verify_throttle,
    humanfmt::HumanFmt,
    metrics::{self, Counter},
    swrite,
    uncacheables::UNCACHEABLES_MAX,
};

use super::{
    fmt::{
        Count, Gauge, Level, Nonzero, RelTime, Segment, StackBar, Unit, alert_if, now_epoch,
        warn_if,
    },
    table::{DetailsList, Highlights, Kind},
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

/// A counter shown with its share of a split, `hits (pct)`: the row keeps
/// its own figure for the scripts, where a `hits / misses` pair would lose
/// it.
fn share_row(
    t: &mut DetailsList,
    label: &'static str,
    tooltip: &'static str,
    value: u64,
    rest: u64,
) {
    t.entry(label)
        .tip(tooltip)
        .figure(value)
        .value(format_args!(
            "{}{}",
            Count(value),
            OptPctSuffix {
                num: value,
                total: value + rest,
            }
        ));
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
#[expect(
    clippy::struct_excessive_bools,
    reason = "one independent switch per configuration-gated row set"
)]
struct Shown {
    /// `https_upgrade_mode` other than `Never`.
    https_upgrade: bool,
    /// `https_tunnel_enabled`.
    tunnels: bool,
    /// `verify_checksums`: the Integrity group, the verify throttle and the
    /// checksum abort cause. Off, an Unverified row reading 0 would claim a
    /// coverage nothing checks.
    verify_checksums: bool,
    /// `min_download_rate` set: the rate-limit cancellations and splice's
    /// client demotion, which only a rate check triggers.
    rate_checks: bool,
    /// `reject_pdiff_requests`.
    pdiff_rejection: bool,
}

impl Shown {
    fn new(config: &Config) -> Self {
        Self {
            https_upgrade: config.https_upgrade_mode != HttpsUpgradeMode::Never,
            tunnels: config.https_tunnel_enabled,
            verify_checksums: config.verify_checksums,
            rate_checks: config.min_download_rate.is_some(),
            pdiff_rejection: config.reject_pdiff_requests,
        }
    }
}

/// The Metrics section as a run of titled subsections, each a heading
/// followed by the [`DetailsList`] its closure fills in.
struct Groups {
    out: String,
    highlights: Highlights,
}

impl Groups {
    fn new() -> Self {
        Self {
            // The full metrics section is comfortably past 40 KB of markup.
            out: String::with_capacity(64 * 1024),
            highlights: Highlights::default(),
        }
    }

    fn group(&mut self, title: &'static str, build: impl FnOnce(&mut DetailsList)) {
        let mut list = DetailsList::new();
        build(&mut list);
        let (html, highlights) = list.finish_counted();
        self.highlights.add(highlights);
        swrite!(self.out, "<h3 class=\"group\">{title}</h3>{html}");
    }

    fn finish(self) -> (String, Highlights) {
        (self.out, self.highlights)
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
            "{} \u{2192} {}{}",
            Count(requests),
            alert_if(Count(served), served > requests),
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
    let funnel = Funnel::load(requests, served);
    t.entry(requests_label)
        .tip(requests_tip)
        .figure(funnel.requests)
        .value(funnel);
    t.bytes_tip(bytes_label, bytes_tip, bytes);
}

/// The section's markup and how many of its rows are highlighted, for the
/// badge its collapsed header carries. `start_epoch` is when the daemon
/// started, which every counter here counts from.
pub(super) fn build_metrics_html(start_epoch: i64) -> (String, Highlights) {
    let shown = Shown::new(global_config());
    let mut g = Groups::new();
    swrite!(
        g.out,
        "<p class=\"scope-note\" data-started=\"{start_epoch}\">Counts since the daemon started, {}: a restart resets them. A highlighted row says when it last moved; live and peak values are marked.</p>",
        RelTime {
            epoch: start_epoch,
            now: now_epoch(),
        }
    );

    build_requests_group(&mut g);
    build_connections_group(&mut g);
    build_refusals_group(&mut g, shown);
    build_admission_group(&mut g, shown);
    build_client_delivery_group(&mut g, shown);
    build_delivery_group(&mut g);
    build_passthrough_group(&mut g);
    build_cache_group(&mut g);
    if shown.verify_checksums {
        build_integrity_group(&mut g);
    }
    build_upstream_group(&mut g, shown);
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
    let status_4xx = metrics::CLIENT_STATUS_4XX.get();
    let status_5xx = metrics::CLIENT_STATUS_5XX.get();
    let status_other = metrics::CLIENT_STATUS_OTHER.get();

    g.group("Requests", |t| {
        t.bar(&StackBar {
            label: "Responses by Class",
            segments: &[
                Segment {
                    name: "2xx",
                    value: status_2xx,
                },
                Segment {
                    name: "3xx",
                    value: status_3xx,
                },
                Segment {
                    name: "4xx",
                    value: status_4xx,
                },
                Segment {
                    name: "5xx",
                    value: status_5xx,
                },
                Segment {
                    name: "other",
                    value: status_other,
                },
            ],
            unit: Unit::Count,
        });
        // Every web-interface request moves these four rows, a script's
        // background refresh included; `polled` lets it discount its own.
        t.entry("Requests \u{2192} Served")
            .tip("Total HTTP requests handled \u{2192} requests whose response body was fully delivered to the client.")
            .polled()
            .figure(all.requests)
            .value(all);
        t.entry("Web UI Requests \u{2192} Served")
            .tip("The same split for the local web interface.")
            .polled()
            .figure(webui.requests)
            .value(webui);
        t.entry("Client 2xx")
            .tip("Successful responses returned to clients. A relayed 203 or 204 counts here without a code row of its own, so the class may exceed 200 + 206; it warns only if the code rows exceed the class, which is a counting bug.")
            .parts(|p| {
                p.entry("Client 200 OK")
                    .polled()
                    .figure(status_200)
                    .value(Count(status_200));
                p.count("Client 206 Partial Content", status_206);
            })
            .polled()
            .figure(status_2xx)
            .value(warn_if(Count(status_2xx), status_200 + status_206 > status_2xx));
        t.entry("Client 3xx")
            .tip("Redirect and not-modified responses returned to clients. A relayed upstream redirect counts here without a code row of its own, so the class may exceed 304; it warns only if 304 exceeds the class, which is a counting bug.")
            .parts(|p| p.count("Client 304 Not Modified", status_304))
            .figure(status_3xx)
            .value(warn_if(Count(status_3xx), status_304 > status_3xx));
        t.entry("Client 4xx")
            .tip("Client-error responses. Not highlighted: pdiff rejections, missing packages relayed from a mirror and web-interface 404 probes land here routinely.")
            .parts(|p| {
                p.count_tip(
                    "Client 410 Gone",
                    "Mostly pdiff requests refused by reject_pdiff_requests (Rejected (pdiff)); a mirror's own 410 is relayed too.",
                    metrics::CLIENT_STATUS_410.get(),
                );
                p.count(
                    "Client 416 Range Not Satisfiable",
                    metrics::CLIENT_STATUS_416.get(),
                );
            })
            .figure(status_4xx)
            .value(Count(status_4xx));
        t.entry("Client 5xx")
            .tip("Server-error responses returned to clients, relayed upstream errors included. A mix of causes with different remedies, so the class only warns; the code rows say which one moved. The rarer codes this proxy answers itself count in the class alone: 501 (unknown method), 505 (unsupported HTTP version) and 508 (Proxy Loops Rejected).")
            .parts(|p| {
                p.signal(
                    "Client 500 Internal Server Error",
                    "The proxy itself failed -- a cache read or write broke (Cache Access Failure), a download aborted for an internal reason (see Storage Errors and the log) -- or a mirror answered 500 and it was relayed. Only warns: the relayed case is the mirror's.",
                    Level::Warn,
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
                p.signal(
                    "Client 504 Gateway Timeout",
                    "Late joiners of a download cancelled because the mirror delivered below min_download_rate (Rate-Limit Cancellations (upstream)), or the mirror itself answered 504. The Mirrors table names the mirror.",
                    Level::Warn,
                    &metrics::CLIENT_STATUS_504,
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
            t.count_tip(
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
            t.count_tip(
                "Timeouts (client header read)",
                "Clients that sent no complete request header within client_idle_timeout (slow-loris shaped, or idle between keep-alive requests). Not highlighted: idle keep-alive connections end this way.",
                metrics::HTTP_TIMEOUT_CLIENT_HEADER.get(),
            );
        }
        if HYPER {
            t.count_tip(
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
                "{}{}",
                Count(connections_accepted),
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
        t.entry("Accept Failures (retried)")
            .tip("accept(2) failures retried after a short pause instead of stopping the daemon: descriptor exhaustion (EMFILE/ENFILE, beneath), kernel memory (ENOBUFS/ENOMEM), or a client that aborted its handshake (ECONNABORTED).")
            .parts(|p| {
                p.signal(
                    "Descriptor Exhaustion",
                    "EMFILE/ENFILE: the process (or the system) ran out of file descriptors, so new connections, cache files and upstream sockets all failed meanwhile. Raise LimitNOFILE, or lower max_connections below it; Capacity: Open File Descriptors shows the peak.",
                    Level::Alert,
                    &metrics::ACCEPT_FD_EXHAUSTED,
                );
            })
            .signal(Level::Warn, &metrics::ACCEPT_TRANSIENT_FAILURES);
    });
}

fn build_refusals_group(g: &mut Groups, shown: Shown) {
    g.group("Request Refusals", |t| {
        if shown.pdiff_rejection {
            t.count_tip(
                "Rejected (pdiff)",
                "Client requests for pdiff resources, refused with 410 because reject_pdiff_requests is set. Not highlighted: apt falls back to the full index.",
                metrics::PDIFF_REJECTED.get(),
            );
        }
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
        t.count_tip(
            "Authorization Rejected (mirror)",
            "Requests refused because the requested mirror is outside allowed_mirrors. The Clients table names the client; add the mirror, or fix the client's sources.",
            metrics::AUTHZ_REJECTED_MIRROR.get(),
        );
        t.count_tip(
            "Authorization Rejected (client)",
            "Requests refused because the source address is outside allowed_proxy_clients. The Clients table names the client.",
            metrics::AUTHZ_REJECTED_CLIENT.get(),
        );
        t.count_tip(
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
            t.count_tip(
                "CONNECT Refused (tunnels disabled)",
                "CONNECT requests refused because https_tunnel_enabled is off. Enable it (with https_tunnel_allowed_mirrors) if clients need HTTPS repositories through this proxy.",
                metrics::TUNNEL_REJECTED_POLICY.get(),
            );
        }
    });
}

fn build_admission_group(g: &mut Groups, shown: Shown) {
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
        if shown.verify_checksums {
            t.signal(
                "Rejected (verify-throttled)",
                "Requests refused with 503 because the resource recently failed checksum verification and is inside its backoff window (verify_checksums_throttle_base, doubling up to verify_checksums_throttle_cap), joiners of a refused download included.",
                Level::Warn,
                &metrics::DOWNLOAD_REJECTED_VERIFY_THROTTLE,
            );
        }
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
        if shown.verify_checksums {
            t.entry("Throttled Resources")
                .kind(Kind::Live)
                .tip("Resources currently refused with 503 because a recent download failed checksum verification (backoff from verify_checksums_throttle_base up to verify_checksums_throttle_cap; cleared by a verified download). A live count, not a total.")
                .value(Nonzero {
                    value: global_verify_throttle().active_len() as u64,
                    level: Level::Warn,
                });
        }
        t.count_tip(
            "Downloads Declined",
            "Registered downloads answered without fetching a body, so not aborts: the upstream status was relayed uncached (a 404, say), the answer was refused (oversize, bad framing, an empty index body), or disk_quota, min_disk_free, the checksum verify throttle or max_passthrough_relays refused it. A max_upstream_downloads refusal never registers and counts in Downloads Rejected (cap) instead.",
            metrics::DOWNLOADS_DECLINED.get(),
        );
    });
}

fn build_client_delivery_group(g: &mut Groups, shown: Shown) {
    g.group("Client Delivery", |t| {
        t.count_tip(
            "Client Disconnected Mid-Body",
            "Clients that hung up before the response body was complete. Not highlighted: apt closes connections it no longer needs. In the hyper backend any peer disconnect during a request counts. The Clients table names the clients.",
            metrics::CLIENT_DISCONNECTED_MID_BODY.get(),
        );
        if SENDFILE {
            // Only the sendfile and splice writers run a timer of their own;
            // hyper's deliveries time out inside hyper, uncounted.
            t.signal(
                "Timeouts (client body write)",
                "Sendfile and splice deliveries aborted because the client accepted no body bytes for http_timeout: a stalled client or a dropped link. The Clients table names the client.",
                Level::Warn,
                &metrics::HTTP_TIMEOUT_CLIENT_BODY,
            );
            t.count_tip(
                "Timeouts (client header write)",
                "Response heads or small proxy-generated responses the client did not accept within http_timeout (sendfile and splice writes).",
                metrics::HTTP_TIMEOUT_CLIENT_HEADER_WRITE.get(),
            );
        }
        if shown.rate_checks {
            t.signal(
                "Rate-Limit Cancellations (client)",
                "Deliveries cancelled because the client read below min_download_rate over rate_check_timeframe. The Clients table names the client; lower min_download_rate if the clients are legitimately slow.",
                Level::Warn,
                &metrics::RATE_LIMIT_CLIENT,
            );
        }
        if SPLICE && shown.rate_checks {
            t.count_tip(
                "Clients Demoted (splice \u{2192} file-serve)",
                "Splice deliveries whose client fell below min_download_rate while the upstream kept pace: instead of cancelling, the client was handed to a task serving the growing cache file, so the download itself goes on at the upstream's speed. A climb points at slow clients (the Clients table) or a min_download_rate set too high.",
                metrics::CLIENTS_DEMOTED.get(),
            );
        }
    });
}

/// The bytes each compiled-in delivery path moved, passthrough relays
/// included, for the Delivery Paths group's bar.
fn delivery_bytes() -> Vec<Segment> {
    let mut segments = Vec::with_capacity(5);
    if SENDFILE {
        segments.push(Segment {
            name: "sendfile",
            value: metrics::BYTES_SERVED_SENDFILE.get(),
        });
    }
    if SPLICE {
        segments.push(Segment {
            name: "splice",
            value: metrics::BYTES_SERVED_SPLICE.get(),
        });
    }
    if HYPER {
        segments.push(Segment {
            name: "copy",
            value: metrics::BYTES_SERVED_COPY.get(),
        });
        segments.push(Segment {
            name: "channel",
            value: metrics::BYTES_SERVED_CHANNEL.get(),
        });
    }
    segments.push(Segment {
        name: "passthrough",
        value: metrics::BYTES_SERVED_PASSTHROUGH.get(),
    });
    segments
}

fn build_delivery_group(g: &mut Groups) {
    let bytes = delivery_bytes();
    g.group("Delivery Paths", |t| {
        t.bar(&StackBar {
            label: "Bytes by Delivery Path",
            segments: &bytes,
            unit: Unit::Bytes,
        });
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

/// A lookup split, `hits / misses (hit share)`.
#[derive(Clone, Copy)]
struct HitsMisses {
    hits: u64,
    misses: u64,
}
impl HitsMisses {
    fn load(hits: &Counter, misses: &Counter) -> Self {
        Self {
            hits: hits.get(),
            misses: misses.get(),
        }
    }
}
impl Display for HitsMisses {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let Self { hits, misses } = *self;
        write!(
            f,
            "{} / {}{}",
            Count(hits),
            Count(misses),
            OptPctSuffix {
                num: hits,
                total: hits + misses,
            },
        )
    }
}

fn build_cache_group(g: &mut Groups) {
    // The parts before their total, which is bumped first.
    let packages = HitsMisses::load(&metrics::PACKAGE_HITS, &metrics::PACKAGE_MISSES);
    let byhash = HitsMisses::load(&metrics::BYHASH_HITS, &metrics::BYHASH_MISSES);
    let all = HitsMisses::load(&metrics::CACHE_HITS, &metrics::CACHE_MISSES);
    let parts_exceed =
        packages.hits + byhash.hits > all.hits || packages.misses + byhash.misses > all.misses;
    let refetched_uptodate = metrics::VOLATILE_REFETCHED_UPTODATE.get();
    let refetched_outofdate = metrics::VOLATILE_REFETCHED_OUTOFDATE.get();
    let refetched = metrics::VOLATILE_REFETCHED.get();
    let volatile = HitsMisses {
        hits: metrics::VOLATILE_HIT.get(),
        misses: refetched,
    };

    g.group("Cache", |t| {
        for (label, lookups) in [
            ("Package Lookups", packages),
            ("By-Hash Lookups", byhash),
            ("Volatile Lookups", volatile),
        ] {
            t.bar(&StackBar {
                label,
                segments: &[
                    Segment {
                        name: "hits",
                        value: lookups.hits,
                    },
                    Segment {
                        name: "misses",
                        value: lookups.misses,
                    },
                ],
                unit: Unit::Count,
            });
        }
        t.entry("Hits / Misses")
            .tip("Cache lookups for permanent resources (packages and by-hash indexes) that found a usable file vs. those that did not, late joiners of an in-flight download counted as misses. The kinds beneath sum to it; it warns only if they exceed it, which is a counting bug.")
            .parts(|p| {
                p.row_tip(
                    "Packages (.deb)",
                    "Package lookups. A low hit share with several clients means they fetch different packages, or name one archive under different mirror hosts and so miss each other's copies: map those hosts onto one with aliases.",
                    packages,
                );
                p.row_tip(
                    "By-Hash Indexes",
                    "Content-addressed index lookups (Acquire-By-Hash). Every index change is a new name and so a miss; hits come from clients updating after one another.",
                    byhash,
                );
            })
            .value(warn_if(all, parts_exceed));
        share_row(
            t,
            "Volatile Hits",
            "Index (Release/Packages/Translation/...) lookups served from the cache inside the freshness window, and their share of all index lookups (hits and the refetches below). A low share with several clients means they update at different times, more than the freshness window apart.",
            volatile.hits,
            volatile.misses,
        );
        t.entry("Volatile Refetches")
            .tip("Volatile requests (indexes) that found no fresh cached copy and needed upstream, whether they fetched it or joined an in-flight fetch. The two outcomes beneath cover the stale-but-present case only; it warns only if they exceed it, which is a counting bug.")
            .parts(|p| {
                p.count_tip(
                    "Refetch Up-to-Date (304)",
                    "Revalidations where upstream confirmed the cached copy was still current.",
                    refetched_uptodate,
                );
                p.count_tip(
                    "Refetch Out-of-Date (200)",
                    "Revalidations where upstream returned changed content.",
                    refetched_outofdate,
                );
            })
            .figure(refetched)
            .value(warn_if(Count(refetched),
                refetched < refetched_uptodate + refetched_outofdate,
            ));
        t.count_tip(
            "Late Joiners (coalesced)",
            "Requests that joined an already in-progress download and shared its data instead of fetching again.",
            metrics::LATE_JOINERS_TOTAL.get(),
        );
        t.entry("Most Late Joiners on One Download")
            .kind(Kind::Peak)
            .tip("The most late joiners any single download has had since startup, counting every client that joined it, including those that left before it finished.")
            .value(Count(metrics::LATE_JOINER_PEAK_PER_DOWNLOAD.get()));
        t.count_tip(
            "Partials Still In Use",
            "Downloads that found their .partial still held by an earlier download of the same file and fetched into a scratch file instead of resuming it.",
            metrics::PARTIAL_CLAIM_CONTENDED.get(),
        );
        t.count_tip(
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
        t.bytes_tip(
            "Reconcile Bytes Repaired",
            "Total size-accounting error corrected by those reconciliation events.",
            metrics::RECONCILE_BYTES_REPAIRED.get(),
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
        t.count_tip(
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
        t.count_tip(
            "Unverified (no known digest)",
            "Resources for which no expected digest was available in the registry; cached unverified (best-effort).",
            metrics::CHECKSUM_UNVERIFIED.get(),
        );
        t.entry("Registry Entries")
            .kind(Kind::Live)
            .tip("In-memory checksum-registry entries (expected digests parsed from Packages/Release indices; lost on restart), against verify_checksums_max_entries. At the cap the oldest digests are dropped, and Re-ingests (touch) climbs: raise the cap to hold the live working set.")
            .value(Gauge {
                current: global_checksum_registry().len() as u64,
                cap: Some(global_config().verify_checksums_max_entries.get() as u64),
                peak: None,
            });
        t.count_tip(
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

fn build_upstream_group(g: &mut Groups, shown: Shown) {
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

    // The causes before their total, which is bumped first. The checksum
    // cause cannot move without verify_checksums; its row is then not shown.
    let abort_causes = [
        (
            "Aborted (upstream failure)",
            "The mirror failed the transfer: connect, head, body, rate or protocol. The Mirrors table names the mirror.",
            Level::Warn,
            &metrics::DOWNLOADS_ABORTED_UPSTREAM,
            true,
        ),
        (
            "Aborted (cache I/O failure)",
            "A cache file could not be written, read back or renamed. Check the cache filesystem (space, permissions, errors) and the Storage Errors rows.",
            Level::Alert,
            &metrics::DOWNLOADS_ABORTED_CACHE,
            true,
        ),
        (
            "Aborted (checksum mismatch)",
            "The whole body arrived but did not match the digest its index promised, so it was discarded: the mirror serves content its own index disagrees with. Same event as Integrity's Mismatch (rejected).",
            Level::Alert,
            &metrics::DOWNLOADS_ABORTED_CHECKSUM,
            shown.verify_checksums,
        ),
        (
            "Aborted (internal failure)",
            "A transfer broke on this side (a pipe, a task): a bug to report.",
            Level::Alert,
            &metrics::DOWNLOADS_ABORTED_INTERNAL,
            true,
        ),
    ]
    .map(|(label, tip, level, signal, visible)| {
        (label, tip, level, signal.get(), signal.last(), visible)
    });
    let cancelled = &metrics::DOWNLOADS_ABORTED_CANCELLED;
    let (cancelled_count, cancelled_last) = (cancelled.get(), cancelled.last());
    // The total warns only for a failure: cancellations alone (clients that
    // walked away) are no alarm, like their own row.
    let failed = abort_causes.iter().any(|(_, _, _, value, _, _)| *value > 0);
    let aborted = &metrics::DOWNLOADS_ABORTED;
    let (aborted_count, aborted_last) = (aborted.get(), aborted.last());

    g.group("Upstream", |t| {
        t.bytes_tip(
            "Bytes Downloaded",
            "Total bytes fetched from upstream mirrors.",
            metrics::BYTES_DOWNLOADED_UPSTREAM.get(),
        );
        t.entry("2xx")
            .tip("Successful responses received from upstream mirrors. Warns only if the 200 and 206 rows exceed it, which is a counting bug; another 2xx code counts here without a row of its own.")
            .parts(|p| {
                p.count("200 OK", status_200);
                p.count_tip(
                    "206 Partial Content",
                    "Answers to a resumed download's Range request.",
                    status_206,
                );
            })
            .figure(status_2xx)
            .value(warn_if(Count(status_2xx), status_200 + status_206 > status_2xx));
        t.entry("3xx")
            .tip("Redirect and not-modified responses from upstream. Warns only if the individual 3xx rows exceed it, which is a counting bug; another 3xx code counts here without a row of its own.")
            .parts(|p| {
                p.count("301 Moved Permanently", status_301);
                p.count("302 Found", status_302);
                p.count("304 Not Modified", status_304);
                p.count("307 Temporary Redirect", status_307);
                p.count("308 Permanent Redirect", status_308);
            })
            .figure(status_3xx)
            .value(warn_if(Count(status_3xx),
                status_301 + status_302 + status_304 + status_307 + status_308 > status_3xx,
            ));
        t.count_tip(
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
            .tip("Registered upstream downloads that ended without being cached; the causes beneath split them and sum to this. Warns once a failure cause moved, not for cancellations alone.")
            .last(aborted_last)
            .parts(|p| {
                for (label, tip, level, value, last, visible) in abort_causes {
                    if !visible {
                        continue;
                    }
                    p.entry(label)
                        .tip(tip)
                        .last(last)
                        .figure(value)
                        .value(Nonzero { value, level });
                }
                p.entry("Aborted (cancelled)")
                    .tip("The download was dropped without a verdict, typically because every client it served went away. No alarm on its own; a climb together with client disconnects points at the clients.")
                    .last(cancelled_last)
                    .figure(cancelled_count)
                    .value(Count(cancelled_count));
            })
            .figure(aborted_count)
            .value(warn_if(Count(aborted_count), failed));
        t.count_tip(
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
        if shown.rate_checks {
            t.signal(
                "Rate-Limit Cancellations (upstream)",
                "Downloads cancelled because the mirror delivered below min_download_rate over rate_check_timeframe (their joiners are answered 504). The Mirrors table names the mirror; lower min_download_rate if the mirror is legitimately slow.",
                Level::Warn,
                &metrics::RATE_LIMIT_UPSTREAM,
            );
        }
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
                "Hyper-backend upstream errors after the response head arrived, while streaming the body (a reset, a read or TLS failure, a read timeout). A body that ended before its announced length, or broke its chunked framing, counts as a Protocol Violation instead, as in splice.",
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
        t.count_tip(
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
                p.count_tip(
                    "HTTPS Upgrade Succeeded",
                    "Upgrade attempts that completed over HTTPS.",
                    upgrade_succeeded,
                );
                p.count_tip(
                    "HTTPS Upgrade Reverted",
                    "Auto-mode soft give-ups that fell back to plain HTTP. A mirror that keeps reverting has no working HTTPS: list it in http_only_mirrors.",
                    upgrade_reverted,
                );
                p.count_tip(
                    "HTTPS Upgrade Failed",
                    "Terminal upgrade failures: Always-mode exhaustion, or a non-connect transport error in any mode. The splice backend also counts an Auto-mode host where both schemes failed here, not as a revert.",
                    upgrade_failed,
                );
            })
            .figure(upgrade_attempted)
            .value(warn_if(Count(upgrade_attempted),
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
    let reused = metrics::POOL_REUSED.get();

    g.group("Upstream Connection Pool", |t| {
        t.bar(&StackBar {
            label: "Upstream Connections",
            segments: &[
                Segment {
                    name: "reused",
                    value: reused,
                },
                Segment {
                    name: "new",
                    value: pool_new,
                },
            ],
            unit: Unit::Count,
        });
        share_row(
            t,
            "Pool Reused",
            "Upstream requests served from an already-open pooled connection, and their share of all upstream connections the splice backend used (reused and new). The misses under Pool New say why a request had to open one.",
            reused,
            pool_new,
        );
        t.entry("Pool New")
            .tip("Newly opened upstream connections. Every new connection falls through from exactly one miss arm, but a miss whose connect then fails opens none, so the misses beneath may exceed it; it warns only if it exceeds their sum, which is a counting bug.")
            .parts(|p| {
                p.count_tip(
                    "Pool Miss (empty)",
                    "No pooled connection was available for the host.",
                    miss_empty,
                );
                p.count_tip(
                    "Pool Miss (dead)",
                    "The pooled connection had been closed by the peer.",
                    miss_dead,
                );
                p.count_tip(
                    "Pool Miss (failed)",
                    "The in-flight request on a pooled connection failed and was retried on a fresh one.",
                    miss_failed,
                );
                p.count_tip(
                    "Pool Miss (no scheme)",
                    "No cached scheme for the host, so the pool was bypassed.",
                    miss_no_scheme,
                );
            })
            .figure(pool_new)
            .value(warn_if(Count(pool_new),
                pool_new > miss_empty + miss_dead + miss_failed + miss_no_scheme,
            ));
        t.count_tip(
            "Pool Return-Evicted",
            "Connections evicted at the point they were returned to a full per-host slot.",
            metrics::POOL_RETURN_EVICTED.get(),
        );
    });
}

fn build_tunnels_group(g: &mut Groups) {
    g.group("HTTPS Tunnels", |t| {
        t.count_tip(
            "Connects (total)",
            "HTTPS-tunnel CONNECT requests accepted since the daemon started. The live count and peak are in the Capacity section.",
            metrics::TUNNEL_CONNECTS_TOTAL.get(),
        );
        t.bytes_tip(
            "Bytes (client \u{2192} upstream)",
            "Bytes copied client-to-upstream through tunnels, however the tunnel ended (cleanly, idle-closed or failed), including bytes pipelined behind the CONNECT request.",
            metrics::BYTES_TUNNELED_CLIENT_TO_UPSTREAM.get(),
        );
        t.bytes_tip(
            "Bytes (upstream \u{2192} client)",
            "Bytes copied upstream-to-client through tunnels, however the tunnel ended (cleanly, idle-closed or failed).",
            metrics::BYTES_TUNNELED_UPSTREAM_TO_CLIENT.get(),
        );
        t.count_tip(
            "Rejected (policy)",
            "CONNECT requests refused because their port is outside https_tunnel_allowed_ports.",
            metrics::TUNNEL_REJECTED_POLICY.get(),
        );
        t.count_tip(
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
        t.count_tip(
            "Closed (idle)",
            "Established tunnels torn down after client_idle_timeout without a byte in either direction. Informational: idle sockets reclaimed, not failures.",
            metrics::TUNNEL_IDLE_CLOSED.get(),
        );
    });
}

/// When the last cleanup run finished, labelled when it failed: an aborted
/// run alerts (the cache could not shrink at all), failed steps warn.
struct LastRun {
    finished: RelTime,
    failures: u64,
}
impl Display for LastRun {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let Self { finished, failures } = self;
        write!(f, "{finished}")?;
        match *failures {
            0 => Ok(()),
            metrics::CLEANUP_ABORTED => write!(f, " {}", alert_if("aborted", true)),
            1 => write!(f, " {}", warn_if("1 step failed", true)),
            n => write!(f, " {}", warn_if(format_args!("{n} steps failed"), true)),
        }
    }
}

fn build_cleanup_group(g: &mut Groups) {
    g.group("Cleanup", |t| {
        // The part before its total, which is bumped first.
        let byhash_unreferenced = metrics::CLEANUP_BYHASH_UNREFERENCED.get();
        let evictions = metrics::CLEANUP_EVICTIONS.get();
        t.entry("Evictions (total)")
            .tip("Cache files removed by the background cleanup across all runs since the daemon started, checksum mismatches included.")
            .parts(|p| {
                p.count_tip(
                    "By-Hash Unreferenced",
                    "By-hash index files reclaimed because their digest was absent from the mirror's current Release set. The other by-hash evictions age out via byhash_retention_days: no current Release could be read, or it does not cover the file's hash algorithm.",
                    byhash_unreferenced,
                );
            })
            .figure(evictions)
            .value(warn_if(Count(evictions), byhash_unreferenced > evictions));
        t.bytes_tip(
            "Bytes Reclaimed (total)",
            "Disk space reclaimed by the background cleanup across all runs since the daemon started.",
            metrics::CLEANUP_BYTES_RECLAIMED.get(),
        );
        t.signal(
            "Checksum Mismatches",
            "Cached files cleanup removed because their content no longer matched the digest in the mirror's current Packages index: disk corruption, or a mirror that re-issued a file under the same name. The Mirrors table names the mirror; download-time mismatches count under Integrity, Mismatch (rejected).",
            Level::Alert,
            &metrics::CLEANUP_CHECKSUM_MISMATCHES,
        );
        t.count_tip(
            "Checksum Skips",
            "Digest verifications skipped because the file was already verified in an earlier cleanup cycle and is unchanged (same inode, size and expected digest).",
            metrics::CLEANUP_CHECKSUM_SKIPS.get(),
        );
        // Loaded first: it is set after the figures, so finding it set means
        // they are this run's.
        let finished_at = metrics::LAST_CLEANUP_FINISHED_AT.get();
        if finished_at == 0 {
            t.row_tip(
                "Last Run",
                "No cleanup has run since the daemon started. Maintenance shows the last run recorded in the database, which survives restarts.",
                "none since start",
            );
        } else {
            t.entry("Last Run")
                .tip("When this process's most recent cleanup run finished, and whether it failed: aborted (the mirror list could not be read, so nothing was reclaimed) or some steps failed (a mirror task that panicked, a directory that could not be read, an index that could not be fetched or parsed so a mirror's sweep was skipped, the rescan after it). The log names each. Maintenance shows the last run from the database.")
                .value(LastRun {
                    finished: RelTime {
                        epoch: i64::try_from(finished_at).unwrap_or(i64::MAX),
                        now: now_epoch(),
                    },
                    failures: metrics::LAST_CLEANUP_FAILURES.get(),
                });
            t.row_tip(
                "Last Run Duration",
                "Wall-clock time the most recent cleanup run took.",
                HumanFmt::Time(std::time::Duration::from_secs(
                    metrics::LAST_CLEANUP_DURATION_SECS.get(),
                )),
            );
            t.row_tip(
                "Last Run Files Removed",
                "Cache files removed by the most recent cleanup run.",
                Count(metrics::LAST_CLEANUP_FILES_REMOVED.get()),
            );
            t.row_tip(
                "Last Run Bytes Reclaimed",
                "Disk space reclaimed by the most recent cleanup run.",
                HumanFmt::Size(metrics::LAST_CLEANUP_BYTES_RECLAIMED.get()),
            );
        }
    });
}

fn build_database_group(g: &mut Groups) {
    g.group("Database", |t| {
        t.count_tip(
            "Commands Sent",
            "Commands handed to the database task since the daemon started. Its queue is a gauge in the Capacity section.",
            metrics::DB_COMMANDS_SENT.get(),
        );
        t.signal(
            "Queue Found Full",
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
        t.count_tip(
            "Commands Dropped (shutdown)",
            "Commands discarded because the database task had already stopped. Not highlighted: a graceful shutdown drops the tail of the telemetry.",
            metrics::DB_COMMANDS_DROPPED_SHUTDOWN.get(),
        );
        t.count_tip(
            "Batch Flushes (by size)",
            "Batches flushed because they reached db_batch_flush_max_count. Under load this should dominate the by-time counter.",
            metrics::DB_BATCH_FLUSHES_BY_SIZE.get(),
        );
        t.count_tip(
            "Batch Flushes (by time)",
            "Batches flushed because db_batch_flush_interval_secs expired. Idle periods favour this over the by-size counter.",
            metrics::DB_BATCH_FLUSHES_BY_TIME.get(),
        );
        t.count_tip(
            "Batch Flushes (on shutdown)",
            "Batches flushed as part of the shutdown drain.",
            metrics::DB_BATCH_FLUSHES_ON_SHUTDOWN.get(),
        );
        t.entry("Peak Batch Size")
            .kind(Kind::Peak)
            .tip("Most commands coalesced into a single flush since startup, against db_batch_flush_max_count, which flushes a batch once it is reached.")
            .value(Gauge {
                current: metrics::DB_BATCH_SIZE_PEAK.get(),
                cap: Some(global_config().db_batch_flush_max_count.get() as u64),
                peak: None,
            });
        t.entry("Mirror Cache Entries")
            .kind(Kind::Live)
            .tip("Process-local mirror-id cache: hydrated at startup, grows on each newly observed mirror, never evicted.")
            .value(Count(metrics::DB_MIRROR_CACHE_ENTRIES.get()));
        let (mirror_hits, mirror_misses) = (
            metrics::DB_MIRROR_CACHE_HITS.get(),
            metrics::DB_MIRROR_CACHE_MISSES.get(),
        );
        share_row(
            t,
            "Mirror Cache Hits",
            "Mirror-id lookups served from the process-local cache, and their share of all lookups. Near 100% once warm: a miss happens only for a mirror first seen since startup.",
            mirror_hits,
            mirror_misses,
        );
        t.count_tip(
            "Mirror Cache Misses",
            "Mirror-id lookups that had to reach the database.",
            mirror_misses,
        );
        t.count_tip(
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
    use super::{Config, HttpsUpgradeMode, LastRun, RelTime, Shown, metrics};

    #[test]
    fn a_failed_cleanup_run_is_labelled() {
        let run = |failures| {
            LastRun {
                finished: RelTime {
                    epoch: 1_000,
                    now: 1_060,
                },
                failures,
            }
            .to_string()
        };
        assert!(!run(0).contains("class="), "{}", run(0));
        assert!(
            run(metrics::CLEANUP_ABORTED).ends_with(" <span class=\"alert\">aborted</span>"),
            "{}",
            run(metrics::CLEANUP_ABORTED)
        );
        assert!(
            run(1).ends_with(" <span class=\"warn\">1 step failed</span>"),
            "{}",
            run(1)
        );
        assert!(
            run(3).ends_with(" <span class=\"warn\">3 steps failed</span>"),
            "{}",
            run(3)
        );
    }

    #[test]
    fn rows_follow_the_build_and_the_config() {
        let mut off = Config::default();
        off.https_upgrade_mode = HttpsUpgradeMode::Never;
        off.https_tunnel_enabled = false;
        off.verify_checksums = false;
        off.min_download_rate = None;
        off.reject_pdiff_requests = false;
        assert_eq!(
            Shown::new(&off),
            Shown {
                https_upgrade: false,
                tunnels: false,
                verify_checksums: false,
                rate_checks: false,
                pdiff_rejection: false,
            }
        );
        for mode in [HttpsUpgradeMode::Auto, HttpsUpgradeMode::Always] {
            let mut on = Config::default();
            on.https_upgrade_mode = mode;
            on.https_tunnel_enabled = true;
            assert_eq!(
                Shown::new(&on),
                Shown {
                    https_upgrade: true,
                    tunnels: true,
                    // The defaults verify, rate-check and refuse pdiffs.
                    verify_checksums: true,
                    rate_checks: true,
                    pdiff_rejection: true,
                },
                "{mode:?}"
            );
        }
    }
}
