//! The collapsed Metrics section of the dashboard: every counter in
//! `metrics.rs`, grouped by subsystem, with the alert/warn policy applied per
//! row.

use std::fmt::{self, Display, Formatter};

use crate::{
    global_checksum_registry, global_verify_throttle, humanfmt::HumanFmt, metrics,
    tunnel_limiter::active_tunnels, uncacheables::UNCACHEABLES_MAX,
};

use super::{
    fmt::{AlertNonzero, WarnNonzero, alert_if, warn_if},
    table::DetailsTable,
};

pub(super) fn build_metrics_html() -> String {
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

    let proc_cache_hits = metrics::CACHE_HITS.get();
    let proc_cache_misses = metrics::CACHE_MISSES.get();
    let proc_cache_lookups = proc_cache_hits + proc_cache_misses;
    let requests_total = metrics::REQUESTS_TOTAL.get();
    let served_total = metrics::SERVED_TOTAL.get();
    let webui_requests = metrics::WEBUI_REQUESTS.get();
    let served_webui = metrics::SERVED_WEBUI.get();
    let connections_accepted = metrics::CONNECTIONS_ACCEPTED.get();

    let mut t = DetailsTable::new();
    t.row_tip(
        "Total Requests \u{2192} Served (Web UI Requests \u{2192} Served) / Connections Accepted",
        "Total HTTP requests handled \u{2192} requests whose response body was fully delivered to the client; same split for the web interface. Plus TCP connections accepted from clients since the daemon started.",
        format_args!(
            "{requests_total} \u{2192} {}{} ({webui_requests} \u{2192} {}{}) / {connections_accepted}{}",
            alert_if(served_total, served_total > requests_total),
            OptPctSuffix {
                num: served_total,
                total: requests_total,
            },
            alert_if(served_webui, served_webui > webui_requests),
            OptPctSuffix {
                num: served_webui,
                total: webui_requests,
            },
            OptReqPerConn {
                requests: requests_total,
                connections: connections_accepted,
            }
        ),
    );
    t.row_tip(
        "Cache Hits / Misses",
        "Cache lookups for permanent (non-volatile) resources that found a usable file vs. those that did not.",
        format_args!(
            "{proc_cache_hits} / {proc_cache_misses}{}",
            OptPctSuffix {
                num: proc_cache_hits,
                total: proc_cache_lookups,
            }
        ),
    );
    {
        let refetched = metrics::VOLATILE_REFETCHED.get();
        let refetched_uptodate = metrics::VOLATILE_REFETCHED_UPTODATE.get();
        let refetched_outofdate = metrics::VOLATILE_REFETCHED_OUTOFDATE.get();
        t.row_tip(
            "Volatile Hits / Refetches (up-to-date / out-of-date)",
            "Volatile-resource (Release/Packages/Translation/...) cache hits within the freshness window vs. revalidations against upstream, split into still up-to-date (304) and changed (200).",
            format_args!(
                "{} / {} ({} / {})",
                metrics::VOLATILE_HIT.get(),
                // Subset invariant: UPTODATE + OUTOFDATE only count the
                // stale-but-present case; the volatile-not-found case bumps
                // REFETCHED without either subset, so REFETCHED >= sum is the
                // true invariant. Warn only on the impossible reverse direction.
                warn_if(refetched, refetched < refetched_uptodate + refetched_outofdate),
                refetched_uptodate,
                refetched_outofdate,
            ),
        );
    }
    t.row_tip(
        "Integrity Verified",
        "Downloaded resources (pool .debs, by-hash files, Packages indices) whose content hash matched a known digest.",
        metrics::CHECKSUM_VERIFIED.get(),
    );
    t.row_tip(
        "Integrity Mismatch (rejected)",
        "Resources rejected because their content hash did not match the expected digest. Non-zero indicates a corrupt or tampered upstream response.",
        AlertNonzero(metrics::CHECKSUM_MISMATCH.get()),
    );
    t.row_tip(
        "Integrity Unverified (no known digest)",
        "Resources for which no expected digest was available in the registry; cached unverified (best-effort).",
        metrics::CHECKSUM_UNVERIFIED.get(),
    );
    t.row_tip(
        "Integrity Registry Entries",
        "In-memory checksum-registry entries (expected digests parsed from Packages/Release indices; lost on restart).",
        global_checksum_registry().len(),
    );
    t.row_tip(
        "Integrity Throttled Resources",
        "Resources currently rejected with 503 because a recent download failed checksum verification (exponential backoff; cleared by a successfully verified download).",
        WarnNonzero(global_verify_throttle().active_len() as u64),
    );
    {
        let status_2xx = metrics::CLIENT_STATUS_2XX.get();
        let status_200 = metrics::CLIENT_STATUS_200.get();
        let status_206 = metrics::CLIENT_STATUS_206.get();
        let status_3xx = metrics::CLIENT_STATUS_3XX.get();
        let status_304 = metrics::CLIENT_STATUS_304.get();
        t.row_tip(
            "Client Status (2xx / 3xx / 4xx / 5xx / other)",
            "Response status classes returned to clients.",
            format_args!(
                "{} / {} / {} / {} / {}",
                warn_if(status_2xx, status_2xx != status_200 + status_206),
                warn_if(status_3xx, status_3xx != status_304),
                metrics::CLIENT_STATUS_4XX.get(), // do not warn due to pdiff rejections, and 404 web interface requests
                AlertNonzero(metrics::CLIENT_STATUS_5XX.get()),
                WarnNonzero(metrics::CLIENT_STATUS_OTHER.get()),
            ),
        );
        t.row_tip(
            "Client 200 OK / 206 Partial Content / 304 Not Modified / 410 Gone / 416 Range Not Satisfiable",
            "Selected response status codes returned to clients.",
            format_args!(
                "{} / {} / {} / {} / {}",
                status_200,
                status_206,
                status_304,
                metrics::CLIENT_STATUS_410.get(),
                metrics::CLIENT_STATUS_416.get(),
            ),
        );
    }
    {
        let status_2xx = metrics::UPSTREAM_STATUS_2XX.get();
        let status_3xx = metrics::UPSTREAM_STATUS_3XX.get();
        let status_200 = metrics::UPSTREAM_STATUS_200.get();
        let status_301 = metrics::UPSTREAM_STATUS_301.get();
        let status_302 = metrics::UPSTREAM_STATUS_302.get();
        let status_304 = metrics::UPSTREAM_STATUS_304.get();
        let status_307 = metrics::UPSTREAM_STATUS_307.get();
        let status_308 = metrics::UPSTREAM_STATUS_308.get();

        t.row_tip(
            "Upstream Status (2xx / 3xx / 4xx / 5xx / other)",
            "Response status classes received from upstream mirrors.",
            format_args!(
                "{} / {} / {} / {} / {}",
                warn_if(status_2xx, status_2xx != status_200),
                warn_if(
                    status_3xx,
                    status_3xx != status_301 + status_302 + status_304 + status_307 + status_308
                ),
                metrics::UPSTREAM_STATUS_4XX.get(),
                WarnNonzero(metrics::UPSTREAM_STATUS_5XX.get()),
                WarnNonzero(metrics::UPSTREAM_STATUS_OTHER.get()),
            ),
        );
        t.row_tip(
            "Upstream 200 OK / 301 Moved Permanently / 302 Found / 304 Not Modified / 307 Temporary Redirect / 308 Permanent Redirect",
            "Selected response status codes received from upstream mirrors.",
            format_args!("{status_200} / {status_301} / {status_302} / {status_304} / {status_307} / {status_308}"),
        );
    }
    t.row_tip(
        "Rejected Requests (pdiff / unsafe path / quota hit / oversize / verify-throttled)",
        "Client requests rejected before serving: pdiff requests, requests with unsafe paths, downloads denied because the configured disk quota is exhausted, downloads rejected because the upstream object size exceeded max_object_size, and downloads rejected because the resource recently failed checksum verification.",
        format_args!(
            "{} / {} / {} / {} / {}",
            metrics::PDIFF_REJECTED.get(),
            WarnNonzero(metrics::UNSAFE_PATH_REJECTED.get()),
            WarnNonzero(metrics::DOWNLOAD_REJECTED_QUOTA.get()),
            WarnNonzero(metrics::DOWNLOAD_REJECTED_OVERSIZE.get()),
            WarnNonzero(metrics::DOWNLOAD_REJECTED_VERIFY_THROTTLE.get())
        ),
    );
    t.row_tip(
        "Uncacheable Evictions",
        "Recent uncacheable (host, path) entries evicted from the in-memory ring buffer because of overflow.",
        format_args!(
            "{}",
            WarnNonzero(
                metrics::UNCACHEABLE
                    .get()
                    .saturating_sub(UNCACHEABLES_MAX.get() as u64)
            )
        ),
    );
    t.row_tip(
        "Client Disconnected Mid-Body",
        "Clients that disconnected before the response body was fully delivered.",
        metrics::CLIENT_DISCONNECTED_MID_BODY.get(),
    );
    t.row_tip(
        "Rate-Limit Cancellations (upstream / client)",
        "Transfers cancelled because the configured minimum download rate was not met on the upstream or client side.",
        format_args!(
            "{} / {}",
            metrics::RATE_LIMIT_UPSTREAM.get(),
            metrics::RATE_LIMIT_CLIENT.get(),
        ),
    );
    t.row_tip(
        "Upstream Connect Failures (splice, TCP / TLS)",
        "Splice-path upstream connection failures, separated into TCP setup and TLS handshake failures.",
        format_args!(
            "{} / {}",
            WarnNonzero(metrics::UPSTREAM_CONNECT_FAILED.get()),
            WarnNonzero(metrics::UPSTREAM_TLS_FAILED.get())
        ),
    );
    {
        let requests = metrics::REQUESTS_MMAP.get();
        let served = metrics::SERVED_MMAP.get();
        t.row_tip(
            "Delivery (mmap) requests \u{2192} served / bytes",
            "Cached responses served via memory-mapped file I/O: requests that entered this path \u{2192} requests whose body was fully delivered, and total bytes delivered.",
            format_args!(
                "{requests} \u{2192} {}{} / {}",
                alert_if(served, served > requests),
                OptPctSuffix {
                    num: served,
                    total: requests,
                },
                HumanFmt::Size(metrics::BYTES_SERVED_MMAP.get())
            ),
        );
    }
    {
        let requests = metrics::REQUESTS_SENDFILE.get();
        let served = metrics::SERVED_SENDFILE.get();
        t.row_tip(
            "Delivery (sendfile) requests \u{2192} served / bytes",
            "Cached responses served via Linux sendfile(2) zero-copy: requests that entered this path \u{2192} requests whose body was fully delivered, and total bytes delivered.",
            format_args!(
                "{requests} \u{2192} {}{} / {}",
                alert_if(served, served > requests),
                OptPctSuffix {
                    num: served,
                    total: requests,
                },
                HumanFmt::Size(metrics::BYTES_SERVED_SENDFILE.get())
            ),
        );
    }
    {
        let requests = metrics::REQUESTS_SPLICE.get();
        let served = metrics::SERVED_SPLICE.get();
        t.row_tip(
            "Delivery (splice) requests \u{2192} served / bytes",
            "Responses streamed from upstream to client via Linux splice(2) zero-copy (small userspace-written tails such as header prefixes and kTLS handshake spill included): requests that entered this path \u{2192} requests whose body was fully delivered, and total bytes delivered.",
            format_args!(
                "{requests} \u{2192} {}{} / {}",
                alert_if(served, served > requests),
                OptPctSuffix {
                    num: served,
                    total: requests,
                },
                HumanFmt::Size(metrics::BYTES_SERVED_SPLICE.get())
            ),
        );
    }
    {
        let requests = metrics::REQUESTS_COPY.get();
        let served = metrics::SERVED_COPY.get();
        t.row_tip(
            "Delivery (copy) requests \u{2192} served / bytes",
            "Cached responses served via plain userspace read/write copy: requests that entered this path \u{2192} requests whose body was fully delivered, and total bytes delivered.",
            format_args!(
                "{requests} \u{2192} {}{} / {}",
                alert_if(served, served > requests),
                OptPctSuffix {
                    num: served,
                    total: requests,
                },
                HumanFmt::Size(metrics::BYTES_SERVED_COPY.get())
            ),
        );
    }
    {
        let requests = metrics::REQUESTS_CHANNEL.get();
        let served = metrics::SERVED_CHANNEL.get();
        t.row_tip(
            "Delivery (channel, late-joiner) requests \u{2192} served / bytes",
            "Late-joiner responses streamed via the hyper ChannelBody path while an upstream download is still in flight: requests that entered this path \u{2192} requests whose body was fully delivered, and total bytes delivered.",
            format_args!(
                "{requests} \u{2192} {}{} / {}",
                alert_if(served, served > requests),
                OptPctSuffix {
                    num: served,
                    total: requests,
                },
                HumanFmt::Size(metrics::BYTES_SERVED_CHANNEL.get())
            ),
        );
    }
    {
        let requests = metrics::REQUESTS_PASSTHROUGH.get();
        let served = metrics::SERVED_PASSTHROUGH.get();
        t.row_tip(
            "Delivery (passthrough, uncached) requests \u{2192} served / bytes",
            "Uncached responses proxied through to clients without storing anything on disk: requests that entered this path \u{2192} requests whose body was fully delivered, and total bytes delivered.",
            format_args!(
                "{requests} \u{2192} {}{} / {}",
                alert_if(served, served > requests),
                OptPctSuffix {
                    num: served,
                    total: requests,
                },
                HumanFmt::Size(metrics::BYTES_SERVED_PASSTHROUGH.get())
            ),
        );
    }
    t.row_tip(
        "Clients Demoted (splice \u{2192} file-serve)",
        "Splice clients demoted to ordinary cached-file delivery, e.g. because they joined an in-progress download.",
        metrics::CLIENTS_DEMOTED.get(),
    );
    t.row_tip(
        "Upstream Bytes Downloaded",
        "Total bytes fetched from upstream mirrors.",
        format_args!(
            "{}",
            HumanFmt::Size(metrics::BYTES_DOWNLOADED_UPSTREAM.get())
        ),
    );
    t.row_tip(
        "Late Joiners (coalesced, peak per download)",
        "Clients that joined an already in-progress download and shared its data, plus the peak number of concurrent late joiners on a single download.",
        format_args!(
            "{} (peak {})",
            metrics::LATE_JOINERS_TOTAL.get(),
            metrics::LATE_JOINER_PEAK_PER_DOWNLOAD.get(),
        ),
    );
    {
        let pool_new = metrics::POOL_NEW.get();
        let miss_empty = metrics::POOL_MISS_EMPTY.get();
        let miss_dead = metrics::POOL_MISS_DEAD.get();
        let miss_failed = metrics::POOL_MISS_FAILED.get();
        let miss_no_scheme = metrics::POOL_MISS_NO_SCHEME.get();
        // Invariant: every POOL_NEW falls through from exactly one POOL_MISS_*
        // arm, so the four miss counters must sum to POOL_NEW. Warn on
        // mismatch — counting bug or split call site.
        t.row_tip(
            "Upstream Pool (reused / new, miss: empty / dead / failed / no-scheme, return-evicted)",
            "Upstream connection pool counters: reused vs. newly opened connections, miss reasons (pool empty, peer-closed connection, in-flight request error on a pooled connection, no cached scheme so the pool was bypassed), and connections evicted when returned.",
            format_args!(
                "{} / {}, miss: {} / {} / {} / {}, return-evicted {}",
                metrics::POOL_REUSED.get(),
                warn_if(
                    pool_new,
                    pool_new != miss_empty + miss_dead + miss_failed + miss_no_scheme,
                ),
                miss_empty,
                miss_dead,
                miss_failed,
                miss_no_scheme,
                metrics::POOL_RETURN_EVICTED.get(),
            ),
        );
    }
    t.row_tip(
        "HTTP Timeouts (upstream connect / upstream read / client header read / client header write / client body)",
        "Configured-timeout firings on upstream connect, upstream read (header or body bytes), client request-header read, client response-header write, and client response-body write paths.",
        format_args!(
            "{} / {} / {} / {} / {}",
            metrics::HTTP_TIMEOUT_UPSTREAM_CONNECT.get(),
            metrics::HTTP_TIMEOUT_UPSTREAM_READ.get(),
            metrics::HTTP_TIMEOUT_CLIENT_HEADER.get(),
            metrics::HTTP_TIMEOUT_CLIENT_HEADER_WRITE.get(),
            metrics::HTTP_TIMEOUT_CLIENT_BODY.get(),
        ),
    );
    t.row_tip(
        "Unhandled Request Headers",
        "Requests carrying an HTTP header outside the daemon's known set, on the upstream-relay path. Useful as a first-contact discovery signal; the log line itself is debounced.",
        WarnNonzero(metrics::UNHANDLED_REQUEST_HEADERS.get()),
    );
    t.row_tip(
        "Request Read Failures (peer disconnect / protocol error)",
        "Header-read failures before any request was parsed. Peer-disconnect counts normal client closes between keep-alive requests; protocol-error counts oversized or malformed headers and is the abuse signal.",
        format_args!(
            "{} / {}",
            metrics::REQUEST_READ_PEER_DISCONNECT.get(),
            WarnNonzero(metrics::REQUEST_READ_PROTOCOL_ERROR.get()),
        ),
    );
    t.row_tip(
        "Upstream Retries",
        "Upstream requests retried after a transient failure.",
        metrics::UPSTREAM_RETRIES.get(),
    );
    t.row_tip(
        "Upstream Download Cap (transitions / rejections)",
        "Concurrent-upstream-download cap state transitions and downloads rejected because the cap was reached.",
        format_args!(
            "{} / {}",
            metrics::UPSTREAM_DOWNLOAD_CAP_TRANSITIONS.get(),
            metrics::UPSTREAM_DOWNLOAD_REJECTED_CAP.get(),
        ),
    );
    t.row_tip(
        "Downloads Aborted",
        "Active upstream downloads aborted before completion.",
        metrics::DOWNLOADS_ABORTED.get(),
    );
    {
        let attempted = metrics::HTTPS_UPGRADE_ATTEMPTED.get();
        let succeeded = metrics::HTTPS_UPGRADE_SUCCEEDED.get();
        let reverted = metrics::HTTPS_UPGRADE_REVERTED.get();
        let failed = metrics::HTTPS_UPGRADE_FAILED.get();
        t.row_tip(
            "HTTPS Upgrade (attempted / succeeded / reverted / failed, scheme-cache removed)",
            "HTTPS upgrade attempts on plain-HTTP requests (reverted: Auto-mode soft give-up; failed: terminal failure - Always-mode exhaustion or a non-connect transport error in any mode), plus removals from the per-host scheme cache.",
            format_args!(
                "{} / {succeeded} / {reverted} / {failed}, {}",
                warn_if(attempted, attempted != succeeded + reverted + failed),
                metrics::SCHEME_CACHE_REMOVED.get(),
            ),
        );
    }
    t.row_tip(
        "Authorization Rejected (mirror / client / tunnel-mirror / webui)",
        "Requests rejected by mirror, client, HTTPS-tunnel-mirror, or web-interface authorization rules.",
        format_args!(
            "{} / {} / {} / {}",
            metrics::AUTHZ_REJECTED_MIRROR.get(),
            metrics::AUTHZ_REJECTED_CLIENT.get(),
            metrics::AUTHZ_REJECTED_TUNNEL_MIRROR.get(),
            metrics::AUTHZ_REJECTED_WEBUI.get(),
        ),
    );
    t.row_tip(
        "DB Operation Failures",
        "SQLite operations that failed.",
        AlertNonzero(metrics::DB_OPERATION_FAILED.get()),
    );
    t.row_tip(
        "Cache Reconcile (events / bytes repaired)",
        "Cache reconciliation events that repaired on-disk size accounting, and the total bytes corrected.",
        format_args!(
            "{} / {}",
            metrics::RECONCILE_EVENTS.get(),
            HumanFmt::Size(metrics::RECONCILE_BYTES_REPAIRED.get()),
        ),
    );
    t.row_tip(
        "Cache Size Corruption",
        "Overflow or underflow detected in the in-memory total-cache-size accounting (value clamped; repaired by the next reconcile).",
        AlertNonzero(metrics::CACHE_SIZE_CORRUPTION.get()),
    );
    t.row_tip(
        "Upstream Protocol Violations",
        "Mirror responses that broke the HTTP contract: body over- or under-ran the announced Content-Length, missing or mismatched Content-Range, missing Content-Length on a non-volatile fetch, or 206 returned without a Range request.",
        WarnNonzero(metrics::UPSTREAM_PROTOCOL_VIOLATION.get()),
    );
    t.row_tip(
        "Upstream Unsolicited 206",
        "Mirror responses that returned 206 Partial Content for a request the proxy issued without a Range header. Rejected with 502 to avoid cache poisoning. A telemetry slice of Upstream Protocol Violations.",
        WarnNonzero(metrics::UPSTREAM_UNSOLICITED_206.get()),
    );
    t.row_tip(
        "Upstream (hyper) Failures pre-response / body",
        "Hyper-backend upstream failures: pre-response (connect/TLS/request framing) aggregated, and post-response body-stream errors. Splice-path equivalents are reported separately.",
        format_args!(
            "{} / {}",
            WarnNonzero(metrics::UPSTREAM_HYPER_REQUEST_FAILED.get()),
            WarnNonzero(metrics::UPSTREAM_HYPER_BODY_ERR.get()),
        ),
    );
    t.row_tip(
        "Cache I/O Failures",
        "Cached-file syscall failures (write/flush/read/rename/create/stat/open/mmap/seek) on serving, download, scan and cleanup paths, regardless of whether a client response was affected.",
        AlertNonzero(metrics::CACHE_IO_FAILURE.get()),
    );
    t.row_tip(
        "Cache Non-Regular Files",
        "Cache entries observed as non-regular non-directory files (FIFO, socket, device, symlink); also bumped for stray directories on some serving/sweep paths. Bumped by serving paths (which then return 5xx), download paths (which abort), and every directory walk: the startup scan and this dashboard leave the entry in place, cleanup unlinks it (pool/flat/dists/by-hash/tmp).",
        AlertNonzero(metrics::CACHE_NON_REGULAR.get()),
    );
    t.row_tip(
        "Cache Unexpected Directories",
        "Cache entries observed as directories where the cache layout does not allow one (an unknown host at the cache root, a non-layout directory in a mirror, anything in a pool or by-hash leaf). Cleanup leaves the directory in place and emits a warn; the tmp/ subtree is the sole exception where the directory is recursively removed once aged. Operator action is usually required to investigate the stray directory.",
        WarnNonzero(metrics::CACHE_DIRECTORY_UNEXPECTED.get()),
    );
    t.row_tip(
        "Cache Unexpected Regular Files",
        "Cache entries observed as regular files where the cache layout does not allow one (the cache root, a non-deb file directly in a mirror directory, a non-UTF-8-named file cleanup cannot match). The file is left in place with a warn; this is typically an operator artefact (e.g. a hand-placed note) rather than a tampering signal.",
        WarnNonzero(metrics::CACHE_UNEXPECTED_REGULAR.get()),
    );
    t.row_tip(
        "Logstore Evictions",
        "Important-log ring-buffer evictions due to overflow.",
        WarnNonzero(metrics::LOGSTORE_EVICTIONS.get()),
    );
    t.row_tip(
        "kTLS RX Enabled / Permanent Fallbacks / Transient Fallbacks",
        "Connections where kernel-TLS receive offload was enabled and successfully started splicing application data, vs. fallback events: permanent (host blocked from kTLS retries until cooldown expires) or transient (post-`setup_rx` drain race; host not blocked).",
        format_args!(
            "{} / {} / {}",
            metrics::KTLS_RX_ENABLED.get(),
            AlertNonzero(metrics::KTLS_FALLBACK_PERMANENT.get()),
            WarnNonzero(metrics::KTLS_FALLBACK_TRANSIENT.get()),
        ),
    );
    t.row_tip(
        "Cleanup Evictions (total) / Bytes Reclaimed (total)",
        "Background cache-cleanup totals across all runs since the daemon started.",
        format_args!(
            "{} / {}",
            metrics::CLEANUP_EVICTIONS.get(),
            HumanFmt::Size(metrics::CLEANUP_BYTES_RECLAIMED.get())
        ),
    );
    t.row_tip(
        "Cleanup By-Hash Unreferenced (total)",
        "By-hash index files reclaimed because their digest was absent from the mirror's current Release set (a subset of total evictions). The rest age out via byhash_retention_days when no current Release can be read.",
        metrics::CLEANUP_BYHASH_UNREFERENCED.get(),
    );
    t.row_tip(
        "Cleanup Checksum Mismatches",
        "Cache files removed because their content hash did not match the SHA256/SHA512 advertised in the upstream Packages stanza. Non-zero indicates corruption or a mirror inconsistency.",
        AlertNonzero(metrics::CLEANUP_CHECKSUM_MISMATCHES.get()),
    );
    t.row_tip(
        "Cleanup Checksum Skips",
        "Digest verifications skipped because the file was already verified in an earlier cleanup cycle and is unchanged (same inode, size and expected digest).",
        metrics::CLEANUP_CHECKSUM_SKIPS.get(),
    );
    t.row_tip(
        "Last Cleanup",
        "Duration, files removed and bytes reclaimed by the most recent cache-cleanup run.",
        format_args!(
            "{}s, {} files, {}",
            metrics::LAST_CLEANUP_DURATION_SECS.get(),
            metrics::LAST_CLEANUP_FILES_REMOVED.get(),
            HumanFmt::Size(metrics::LAST_CLEANUP_BYTES_RECLAIMED.get())
        ),
    );
    t.row_tip(
        "Tunnel Connects (total / active / peak)",
        "HTTPS-tunnel CONNECT requests accepted, currently active, and peak observed since startup.",
        format_args!(
            "{} / {} / {}",
            metrics::TUNNEL_CONNECTS_TOTAL.get(),
            active_tunnels(),
            metrics::CONNECT_TUNNEL_ACTIVE_PEAK.get(),
        ),
    );
    t.row_tip(
        "Tunnel Bytes (client \u{2192} upstream / upstream \u{2192} client)",
        "Bytes copied through completed CONNECT tunnels in each direction. Only counted when the tunnel exits cleanly.",
        format_args!(
            "{} / {}",
            HumanFmt::Size(metrics::BYTES_TUNNELED_CLIENT_TO_UPSTREAM.get()),
            HumanFmt::Size(metrics::BYTES_TUNNELED_UPSTREAM_TO_CLIENT.get()),
        ),
    );
    t.row_tip(
        "Tunnel Rejected (policy / capacity)",
        "HTTPS-tunnel CONNECT requests rejected by policy or capacity limits.",
        format_args!(
            "{} / {}",
            metrics::TUNNEL_REJECTED_POLICY.get(),
            metrics::TUNNEL_REJECTED_CAPACITY.get()
        ),
    );
    t.row_tip(
        "Tunnel Transfer Failures",
        "Post-acceptance tunnel failures: HTTP upgrade failure, upstream connect failure / timeout, or mid-transfer error. Operationally counts tunnels that were accepted but did not complete cleanly.",
        WarnNonzero(metrics::TUNNEL_TRANSFER_FAILED.get()),
    );
    t.row_tip(
        "Tunnels Closed (idle)",
        "Established CONNECT tunnels torn down after `client_idle_timeout` without a byte in either direction. Informational: idle sockets reclaimed, not failures.",
        metrics::TUNNEL_IDLE_CLOSED.get(),
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
        "Connections Rejected (global cap)",
        "Connections dropped at accept time because `max_connections` was reached. Climbing values mean a flood or a cap sized below the real client population.",
        WarnNonzero(metrics::CONNECTION_REJECTED_GLOBAL_CAP.get()),
    );
    t.finish()
}

// ---------------------------------------------------------------------------
// Page builders
// ---------------------------------------------------------------------------
