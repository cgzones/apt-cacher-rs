//! Process-wide runtime counters surfaced by the web interface.
//!
//! All counters are additive and monotonic from process start, except peak
//! values which track the maximum observed since startup.
//!
//! A counter the dashboard highlights once non-zero (a bad sign: a failure,
//! a refusal, a cap hit) is a [`Signal`], which also stamps when it last
//! moved; everything else is a plain [`Counter`]. Promoting a counter to a
//! highlighted row means changing its type too, or its row cannot say
//! whether the count is history or ongoing.

use std::sync::atomic::{AtomicU64, Ordering};

use http::StatusCode;

#[derive(Debug)]
pub(crate) struct Counter(AtomicU64);

impl Counter {
    #[must_use]
    const fn new() -> Self {
        Self(AtomicU64::new(0))
    }

    pub(crate) fn increment(&self) {
        // Wraparound on `u64::MAX` is acceptable: at one increment per
        // nanosecond it would still take ~584 years to overflow.
        self.0.fetch_add(1, Ordering::Relaxed);
    }

    #[must_use]
    pub(crate) fn get(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }
}

/// A bad-sign counter: a [`Counter`] that also remembers when it last moved.
///
/// Every counter the dashboard highlights once non-zero is one of these, so
/// the page can say whether a lifetime count is history or is happening now
/// ("last: 3 h ago") -- the highlight alone reads the same for a single
/// failure at startup and a mirror failing every minute. The stamp is one
/// wall-clock read (`coarsetime::Clock::now_since_epoch`) and one relaxed
/// store per bump, cheap enough for any site: these counters sit on
/// failure and refusal paths, never on a per-byte one. Request-granular
/// counters that are no alarm stay plain [`Counter`]s.
#[derive(Debug)]
pub(crate) struct Signal {
    count: AtomicU64,
    /// Unix seconds of the latest bump; 0 before the first.
    last: AtomicU64,
}

impl Signal {
    #[must_use]
    const fn new() -> Self {
        Self {
            count: AtomicU64::new(0),
            last: AtomicU64::new(0),
        }
    }

    /// Stamps before it counts, releasing the stamp with the count: a
    /// reader that sees the new count sees its stamp too (see [`Self::last`]).
    pub(crate) fn increment(&self) {
        self.last.store(now_epoch_secs(), Ordering::Relaxed);
        self.count.fetch_add(1, Ordering::Release);
    }

    #[must_use]
    pub(crate) fn get(&self) -> u64 {
        self.count.load(Ordering::Acquire)
    }

    /// Unix seconds of the latest bump, `None` before the first. Read after
    /// [`Self::get`] and the two can disagree by one in-flight bump, which
    /// only ever makes the stamp newer than the count it is shown with: the
    /// count is released after the stamp and acquired before it is read, so
    /// a count never shows without the stamp of its own bump.
    #[must_use]
    pub(crate) fn last(&self) -> Option<u64> {
        match self.last.load(Ordering::Relaxed) {
            0 => None,
            secs => Some(secs),
        }
    }
}

/// The coarse wall clock every [`Signal`] stamp is taken from.
fn now_epoch_secs() -> u64 {
    // Only a clock set to the epoch's first second could store the "never"
    // sentinel; clamp so a bump always reads as a bump.
    coarsetime::Clock::now_since_epoch().as_secs().max(1)
}

/// Cumulative time a limiter spent at its cap since process start: how long
/// requests were being refused or made to wait, which a refusal count alone
/// cannot tell apart (a burst of refusals in one second vs. a cap that is
/// hit all day).
///
/// The limiter calls [`Self::enter`] when an admission brings it to its cap
/// and [`Self::leave`] when a release takes it below; both are idempotent,
/// so a caller that cannot tell whether it was at the cap may call `leave`
/// on every release. Each is a relaxed load in the common case (not at the
/// cap, or already there), an RMW only on a transition. Where the limiter
/// is not updated under a lock, a transition racing an opposite one can end
/// or start a span one release late; the figure is for sizing a cap, not
/// for billing.
pub(crate) struct CapClock {
    /// Coarse monotonic ticks when the current span at the cap began; 0
    /// while below the cap.
    since: AtomicU64,
    /// Ticks spent at the cap in finished spans.
    total: AtomicU64,
}

impl CapClock {
    #[must_use]
    pub(crate) const fn new() -> Self {
        Self {
            since: AtomicU64::new(0),
            total: AtomicU64::new(0),
        }
    }

    /// The limiter reached its cap.
    pub(crate) fn enter(&self) {
        if self.since.load(Ordering::Relaxed) == 0 {
            self.enter_at(now_ticks());
        }
    }

    /// The limiter is below its cap (again).
    pub(crate) fn leave(&self) {
        if self.since.load(Ordering::Relaxed) != 0 {
            self.leave_at(now_ticks());
        }
    }

    /// Whether a span at the cap is running.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn is_at_cap(&self) -> bool {
        self.since.load(Ordering::Relaxed) != 0
    }

    /// Time spent at the cap, the running span included.
    #[must_use]
    pub(crate) fn total(&self) -> std::time::Duration {
        self.total_at(now_ticks())
    }

    fn enter_at(&self, now: u64) {
        // Lost race: another admission started the span already.
        if self
            .since
            .compare_exchange(0, now.max(1), Ordering::Relaxed, Ordering::Relaxed)
            .is_err()
        {}
    }

    fn leave_at(&self, now: u64) {
        let since = self.since.swap(0, Ordering::Relaxed);
        if since != 0 {
            self.total
                .fetch_add(now.saturating_sub(since), Ordering::Relaxed);
        }
    }

    fn total_at(&self, now: u64) -> std::time::Duration {
        let since = self.since.load(Ordering::Relaxed);
        let running = if since == 0 {
            0
        } else {
            now.saturating_sub(since)
        };
        coarsetime::Duration::from_ticks(self.total.load(Ordering::Relaxed) + running).into()
    }
}

/// The coarse monotonic clock every [`CapClock`] span is measured with.
fn now_ticks() -> u64 {
    coarsetime::Instant::now().as_ticks()
}

pub(crate) struct Peak(AtomicU64);

impl Peak {
    #[must_use]
    const fn new() -> Self {
        Self(AtomicU64::new(0))
    }

    pub(crate) fn update(&self, value: u64) {
        // Steady state (no new peak) stays read-only: fetch_max compiles to
        // a CAS loop on x86, an RMW on the shared line even when the stored
        // max already dominates.
        if self.0.load(Ordering::Relaxed) < value {
            self.0.fetch_max(value, Ordering::Relaxed);
        }
    }

    #[must_use]
    pub(crate) fn get(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }
}

/// A counter bumped by an arbitrary amount (`increment_by`). Most are byte
/// counters; the cleanup and database tallies among them count what their
/// name says (`CLEANUP_EVICTIONS` and `CLEANUP_BYHASH_UNREFERENCED` files,
/// `DB_MIRROR_LAST_SEEN_FLUSHED` rows).
///
/// Cache-line aligned for the hot ones, the per-chunk byte counters
/// (`BYTES_SERVED_*`, `BYTES_DOWNLOADED_UPSTREAM`), hit from different
/// worker threads at chunk granularity. Without the alignment, up to eight
/// of them share one 64-byte line and every bump bounces it between cores.
/// There are only 13 accumulators, so the padding is negligible;
/// the ~125 request-granularity `Counter`s stay packed on purpose.
#[repr(align(64))]
pub(crate) struct Accumulator(AtomicU64);

impl Accumulator {
    #[must_use]
    const fn new() -> Self {
        Self(AtomicU64::new(0))
    }

    pub(crate) fn increment_by(&self, value: u64) {
        // Wraparound on `u64::MAX` is acceptable: at one byte per nanosecond
        // it would still take ~584 years to overflow.
        self.0.fetch_add(value, Ordering::Relaxed);
    }

    #[must_use]
    pub(crate) fn get(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }
}

pub(crate) struct StateU64(AtomicU64);

impl StateU64 {
    #[must_use]
    const fn new() -> Self {
        Self(AtomicU64::new(0))
    }

    pub(crate) fn set(&self, value: u64) {
        self.0.store(value, Ordering::Relaxed);
    }

    #[must_use]
    pub(crate) fn get(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }
}

/// Total client requests handled, including web-interface requests.
/// Subtract `WEBUI_REQUESTS` to get proxy-only requests. Counted when the
/// request starts. A request hyper itself refuses while parsing (a hyper-only
/// build, or a connection the sendfile backend handed to hyper for good)
/// never reaches the proxy and counts nowhere, nor in `CLIENT_STATUS_*`.
pub(crate) static REQUESTS_TOTAL: Counter = Counter::new();
/// Requests for which a response body was fully delivered to the client
/// (subset of `REQUESTS_TOTAL`; sum of per-delivery-path `SERVED_*` plus
/// `SERVED_WEBUI`).
pub(crate) static SERVED_TOTAL: Counter = Counter::new();
/// Web interface requests entering `serve_web_interface`. Subset of
/// `REQUESTS_TOTAL` (every `WebUI` request bumps both counters).
pub(crate) static WEBUI_REQUESTS: Counter = Counter::new();
/// Web interface responses fully delivered (subset of `WEBUI_REQUESTS`
/// and `SERVED_TOTAL`).
pub(crate) static SERVED_WEBUI: Counter = Counter::new();
/// TCP connections accepted by the listener (counted at `accept()`,
/// before the ACL and connection-cap checks). Connections subsequently
/// rejected by the client ACLs, `max_connections` or
/// `max_connections_per_client_ip` are included here and also counted in
/// `CONNECTION_REJECTED_ACL`, `CONNECTION_REJECTED_GLOBAL_CAP` or
/// `CONNECTION_REJECTED_PER_IP_CAP`.
pub(crate) static CONNECTIONS_ACCEPTED: Counter = Counter::new();
/// `accept(2)` failures the listener loop retried instead of stopping the
/// daemon: EMFILE/ENFILE (descriptor exhaustion), ENOBUFS/ENOMEM, and
/// ECONNABORTED.  Climbing values mean the process is at its fd budget --
/// check `max_connections` against `LimitNOFILE`.
pub(crate) static ACCEPT_TRANSIENT_FAILURES: Signal = Signal::new();

/// Upstream response class buckets (2xx/3xx/4xx/5xx/other).
pub(crate) static UPSTREAM_STATUS_2XX: Counter = Counter::new();
pub(crate) static UPSTREAM_STATUS_3XX: Counter = Counter::new();
pub(crate) static UPSTREAM_STATUS_4XX: Counter = Counter::new();
pub(crate) static UPSTREAM_STATUS_5XX: Signal = Signal::new();
pub(crate) static UPSTREAM_STATUS_OTHER: Signal = Signal::new();

/// Selected upstream status codes tracked individually
/// (200/206/301/302/304/307/308). 206 is every resumed download's answer.
pub(crate) static UPSTREAM_STATUS_200: Counter = Counter::new();
pub(crate) static UPSTREAM_STATUS_206: Counter = Counter::new();
pub(crate) static UPSTREAM_STATUS_301: Counter = Counter::new();
pub(crate) static UPSTREAM_STATUS_302: Counter = Counter::new();
pub(crate) static UPSTREAM_STATUS_304: Counter = Counter::new();
pub(crate) static UPSTREAM_STATUS_307: Counter = Counter::new();
pub(crate) static UPSTREAM_STATUS_308: Counter = Counter::new();

/// Client response class buckets (2xx/3xx/4xx/5xx/other).
pub(crate) static CLIENT_STATUS_2XX: Counter = Counter::new();
pub(crate) static CLIENT_STATUS_3XX: Counter = Counter::new();
pub(crate) static CLIENT_STATUS_4XX: Counter = Counter::new();
pub(crate) static CLIENT_STATUS_5XX: Signal = Signal::new();
pub(crate) static CLIENT_STATUS_OTHER: Signal = Signal::new();

/// Selected client status codes tracked individually (200/206/304/410/416
/// and the three 5xx codes this proxy answers with itself).
pub(crate) static CLIENT_STATUS_200: Counter = Counter::new();
pub(crate) static CLIENT_STATUS_206: Counter = Counter::new();
pub(crate) static CLIENT_STATUS_304: Counter = Counter::new();
pub(crate) static CLIENT_STATUS_410: Counter = Counter::new();
pub(crate) static CLIENT_STATUS_416: Counter = Counter::new();
/// `500`: a cache access failure or an aborted download (internal failure,
/// cancellation) -- the local side broke -- or a relayed upstream 500.
pub(crate) static CLIENT_STATUS_500: Signal = Signal::new();
/// `502`: an upstream fetch failed or its answer was refused
/// (`"Upstream Error"`, `RejectReason`), or a relayed upstream 502.
pub(crate) static CLIENT_STATUS_502: Signal = Signal::new();
/// `503`: a deliberate refusal (disk quota or `min_disk_free`, the
/// download/passthrough caps, the verify throttle), or a relayed upstream 503.
pub(crate) static CLIENT_STATUS_503: Signal = Signal::new();

/// Volatile-resource hit served from cache within `VOLATILE_CACHE_MAX_AGE`.
/// Ratio against `VOLATILE_REFETCHED` indicates whether max-age is well-tuned.
pub(crate) static VOLATILE_HIT: Counter = Counter::new();
/// Volatile-resource request that found no fresh file (stale on disk or
/// absent), so it needed upstream: it either fetched itself or joined the
/// in-flight fetch (a late joiner, also in `LATE_JOINERS_TOTAL`) -- the
/// volatile counterpart of `CACHE_MISSES`, which counts permanent files
/// only. `VOLATILE_HIT + VOLATILE_REFETCHED` is every volatile lookup.
/// `VOLATILE_REFETCHED_UPTODATE` and `VOLATILE_REFETCHED_OUTOFDATE` are
/// subsets bumped by the fetching request only, covering the
/// stale-but-present case; the volatile-not-found case and joiners bump
/// neither sub-bucket, so their sum is less than or equal to
/// `VOLATILE_REFETCHED`.
pub(crate) static VOLATILE_REFETCHED: Counter = Counter::new();
/// Subset of `VOLATILE_REFETCHED`: stale-but-present, upstream returned 304.
pub(crate) static VOLATILE_REFETCHED_UPTODATE: Counter = Counter::new();
/// Subset of `VOLATILE_REFETCHED`: stale-but-present, upstream returned a fresh body.
pub(crate) static VOLATILE_REFETCHED_OUTOFDATE: Counter = Counter::new();

/// Downloads whose content matched its expected digest before being committed
/// to the cache.
pub(crate) static CHECKSUM_VERIFIED: Counter = Counter::new();
/// Downloads rejected because their content did not match the expected digest.
pub(crate) static CHECKSUM_MISMATCH: Signal = Signal::new();
/// Verifiable-kind downloads committed to the cache without a known expected
/// digest (best-effort coverage gap).
pub(crate) static CHECKSUM_UNVERIFIED: Counter = Counter::new();

/// Cached indexes re-ingested because a request answered from cache found
/// the registry without their digests (restart, eviction, an earlier skip
/// or transient failure). Climbing with every `apt update` means the live
/// working set exceeds `verify_checksums_max_entries`.
pub(crate) static INGEST_TOUCH_TRIGGERED: Counter = Counter::new();
/// Index ingests skipped because the line in front of the ingest permits
/// was full; each is retried on the index's next request.
pub(crate) static INGEST_SKIPPED_QUEUE_FULL: Signal = Signal::new();
/// Index files whose ingest failed for good (too large, corrupt, over the
/// CPU budget); not retried until a commit replaces the file.
pub(crate) static INGEST_FAILED_MARKED: Signal = Signal::new();

/// Body-write failures attributed to the client (`BrokenPipe` /
/// `ConnectionReset` / `ConnectionAborted`).
///
/// Scope per backend:
///   * sendfile / splice — bumped only when the failing write happens
///     mid-body (the helpers see the syscall error directly).
///   * hyper — hyper does not expose per-frame write errors, so the
///     bump fires once per connection on any peer-disconnect surfaced by
///     `serve_connection`. That includes pre-body and between-keepalive
///     disconnects, so the hyper count slightly over-attributes to
///     "mid-body" — interpret as "client peer-disconnects during a
///     hyper-served request lifetime."
pub(crate) static CLIENT_DISCONNECTED_MID_BODY: Counter = Counter::new();

/// Requests rejected with 400 because the path failed safety validation:
/// traversal or control bytes in the whole path (`is_unsafe_cache_path`,
/// `is_unsafe_proxy_path`), or a cached route's field whose percent-decoded
/// value its validator refuses (`ClassifyError::InvalidValue`: a `..`, a
/// `/` smuggled as `%2F`, a control byte).
pub(crate) static UNSAFE_PATH_REJECTED: Signal = Signal::new();
/// Requests rejected because they targeted a `pdiff` resource.
pub(crate) static PDIFF_REJECTED: Counter = Counter::new();

/// Unique `(host, path)` resources marked uncacheable. Bumped only on the
/// first observation that inserts a new ring entry; repeated requests for
/// the same resource do not bump it. Once the count exceeds
/// `UNCACHEABLES_MAX`, the surplus equals the number of ring evictions.
pub(crate) static UNCACHEABLE: Counter = Counter::new();

/// HTTPS CONNECT tunnels accepted.
pub(crate) static TUNNEL_CONNECTS_TOTAL: Counter = Counter::new();
/// CONNECT tunnels rejected by the global tunnel-disabled flag or by the
/// per-port allowlist. Mirror-allowlist denials are tracked separately as
/// `AUTHZ_REJECTED_TUNNEL_MIRROR`.
pub(crate) static TUNNEL_REJECTED_POLICY: Counter = Counter::new();
/// CONNECT tunnels rejected with 429 because their source IP already held
/// `https_tunnel_max_connections_per_client` tunnels (a per-IP cap; there
/// is no global tunnel cap).
pub(crate) static TUNNEL_REJECTED_CAPACITY: Signal = Signal::new();
/// Post-acceptance tunnel failures: the CONNECT was accepted (counted in
/// `TUNNEL_CONNECTS_TOTAL`) but the tunnel did not complete cleanly.
/// Covers hyper's HTTP-upgrade failure and the sendfile backend's failed
/// `200 Connection Established` write (the same event: the client is gone
/// before the relay starts), upstream TCP connect failure / timeout, a
/// failed forward of pipelined client bytes, and mid-transfer errors from
/// `copy_bidirectional_with_sizes`. Climbing values point to flaky
/// upstream tunnels or aborted clients.
pub(crate) static TUNNEL_TRANSFER_FAILED: Signal = Signal::new();
/// Established tunnels torn down because neither side sent a byte for
/// `client_idle_timeout`.  Not a failure: a parked CONNECT socket is
/// reclaimed instead of pinning fds and an upstream connection.
pub(crate) static TUNNEL_IDLE_CLOSED: Counter = Counter::new();
/// Peak concurrent CONNECT tunnels, summed across all source IPs, tracked
/// whether or not a cap is configured.  A global figure: it cannot show how
/// close any single IP came to the per-IP cap
/// `https_tunnel_max_connections_per_client` (see
/// `TUNNEL_REJECTED_CAPACITY` for that cap's refusals).
pub(crate) static CONNECT_TUNNEL_ACTIVE_PEAK: Peak = Peak::new();
/// Time at least one source IP held `https_tunnel_max_connections_per_client`
/// tunnels (so its next CONNECT would be refused).
pub(crate) static TUNNEL_PER_CLIENT_CAP_CLOCK: CapClock = CapClock::new();

/// Plain-HTTP connections rejected at accept time because the per-source-IP
/// cap (`max_connections_per_client_ip`) was reached. Climbing values
/// indicate a noisy or malicious source IP; consider alerting.
pub(crate) static CONNECTION_REJECTED_PER_IP_CAP: Signal = Signal::new();
/// Connections rejected at accept time because the global cap
/// (`max_connections`) was reached.  Climbing values mean the daemon is at
/// its connection budget: either a flood, or a cap sized below the real
/// client population (raise `max_connections` and `LimitNOFILE` together).
pub(crate) static CONNECTION_REJECTED_GLOBAL_CAP: Signal = Signal::new();
/// Connections closed at accept time because the source address passes
/// neither `allowed_proxy_clients` nor `allowed_webif_clients`, so no
/// request from it could be served.  Counted instead of (not in addition
/// to) the per-request `AUTHZ_REJECTED_*` counters, which such a client no
/// longer reaches.
pub(crate) static CONNECTION_REJECTED_ACL: Signal = Signal::new();
/// Requests refused with 508 because their `Via` already named this proxy:
/// the proxy was asked to fetch from itself.  Any value means an
/// `allowed_mirrors` wildcard covers the proxy's own name.
pub(crate) static PROXY_LOOP_REJECTED: Signal = Signal::new();

/// Highest concurrent connection count observed from any single source IP.
/// Only updated while `max_connections_per_client_ip` is enabled (the
/// default; 0 disables it and the per-IP map is then not maintained). Use to size the cap: deploy
/// with a generously high value, watch this peak settle, then lower the
/// cap to a comfortable margin above it.
pub(crate) static PER_CLIENT_IP_PEAK: Peak = Peak::new();
/// Time at least one source IP held `max_connections_per_client_ip`
/// connections (so its next connection would be refused).
pub(crate) static CONNECTION_PER_IP_CAP_CLOCK: CapClock = CapClock::new();

/// HTTP request headers outside the daemon's known set
/// (`warn_once_or_info!("Unhandled HTTP header …")`), counted per header --
/// a request carrying three unknown headers counts three; the log entry
/// itself is debounced.
///
/// Scope: hyper only, and only a request that starts a download in hyper's
/// `serve_new_file_worker` (cache miss or volatile refetch). Cache hits and
/// every splice-fetched request look up headers by name and never trip it.
pub(crate) static UNHANDLED_REQUEST_HEADERS: Counter = Counter::new();

/// Request-header reads that failed before any request was parsed, broken
/// down by whether the peer was the cause (reset/eof) or the byte stream
/// itself was malformed (oversized headers, garbage). Useful for separating
/// "client went away" noise from genuine protocol abuse.
///
/// Scope: only updated by the sendfile backend's manual header-read loop.
/// Hyper parses headers internally and counts nothing here: in
/// `cfg(not(feature = "sendfile"))` builds (non-default) these counters stay
/// at 0, and on a sendfile connection handed over to hyper for good (an
/// HTTP/1.0 request, a request body) its later requests are not counted.
pub(crate) static REQUEST_READ_PEER_DISCONNECT: Counter = Counter::new();
pub(crate) static REQUEST_READ_PROTOCOL_ERROR: Signal = Signal::new();

/// Most file descriptors this process held at once since start, against
/// its soft `RLIMIT_NOFILE`: sampled every few seconds and on each
/// dashboard render (`fd_usage`), and set to the soft limit itself when
/// `accept(2)` fails with `EMFILE`, a spike the samples can miss.
pub(crate) static OPEN_FDS_PEAK: Peak = Peak::new();

/// Peak concurrency: connected clients, in-flight upstream downloads,
/// in-flight client-side downloads.
pub(crate) static CONNECTED_CLIENTS_PEAK: Peak = Peak::new();
/// Peaks the `active_downloads::UpstreamSlot` count -- downloads with an
/// upstream connection open, the unit `max_upstream_downloads` caps -- not
/// the registry's entry count: a download past `begin_rename` (verifying,
/// renaming) holds no slot and does not count.
pub(crate) static ACTIVE_UPSTREAM_DOWNLOADS_PEAK: Peak = Peak::new();
pub(crate) static ACTIVE_CLIENT_DOWNLOADS_PEAK: Peak = Peak::new();

/// Bytes delivered via Linux `sendfile(2)` zero-copy, whichever backend
/// counted the request: besides the sendfile backend's own serves, a splice
/// request's tail served to a demoted client and the already-cached prefix
/// of a resumed splice download go out through `sendfile(2)` and are counted
/// here, under a request counted in `REQUESTS_SPLICE`.
pub(crate) static BYTES_SERVED_SENDFILE: Accumulator = Accumulator::new();
/// Bytes delivered to the client by the splice proxy backend.  The bulk of
/// these traverse Linux `splice(2)` zero-copy (`tee_and_splice`), but the
/// counter also covers the small userspace-write tail that the splice path
/// cannot avoid: the body prefix consumed by the header parser,
/// range-boundary chunks carved from a userspace
/// drain buffer, and the volatile buffered re-fetch path that buffers the
/// entire body in RAM before writing.  All of these sit within a request
/// counted under `REQUESTS_SPLICE`.
pub(crate) static BYTES_SERVED_SPLICE: Accumulator = Accumulator::new();
/// Bytes delivered via plain userspace read/write copy on the hyper backend's
/// cache-hit streaming-file path (`CachedFileBody`, `Mechanism::Stream`).
/// Counted per polled frame and published by `AccountedBody` when the body
/// ends. Splice-path userspace writes are reported under
/// `BYTES_SERVED_SPLICE` instead, since they are inseparable from the
/// request's splice accounting.
pub(crate) static BYTES_SERVED_COPY: Accumulator = Accumulator::new();
/// Bytes streamed from an in-flight download via the hyper `ChannelBody`
/// path (`serve_unfinished_file`): late joiners and the hyper client whose
/// request started the download. Counted per polled frame (when hyper
/// requests the frame, not when the kernel acks the write) and published
/// when the body ends — slightly overcounts on aborted clients vs. the
/// post-write splice/sendfile counters.
pub(crate) static BYTES_SERVED_CHANNEL: Accumulator = Accumulator::new();

/// Bytes proxied uncached. Splice relays count after each client write;
/// hyper counts per polled frame (no post-write hook in its body model) and
/// publishes when the body ends (`AccountedBody`'s `Drop`) — slightly
/// overcounting an aborted client against the post-write splice counts.
pub(crate) static BYTES_SERVED_PASSTHROUGH: Accumulator = Accumulator::new();
pub(crate) static REQUESTS_PASSTHROUGH: Counter = Counter::new();
pub(crate) static SERVED_PASSTHROUGH: Counter = Counter::new();

/// Requests whose upstream connect failed for good: the TCP connect or TLS
/// handshake still failed after the retries and the Auto-mode HTTPS-to-HTTP
/// fallback, so the request was answered without an upstream response.
/// Counted once per request, when its terminal failure is concluded
/// (`transfer_error::UpstreamError::connect`), in every backend: a retried
/// attempt or a fallback that ends up connected counts nothing here (the
/// attempts are `UPSTREAM_RETRIES`, the connect timeouts
/// `HTTP_TIMEOUT_UPSTREAM_CONNECT`).
pub(crate) static UPSTREAM_CONNECT_FAILED: Signal = Signal::new();
/// Requests whose upstream was connected but whose exchange failed before a
/// response head arrived: a reset, an EOF before the header terminator, a
/// read timeout, a failed request write. Counted once per request when its
/// terminal failure is concluded (`transfer_error::UpstreamError::head_io` /
/// `head_transport`), in every backend. A pooled connection that fails this
/// way and is replaced by a fresh one is not terminal and counts only
/// `POOL_MISS_FAILED`; an unparsable or refused head is an
/// `UPSTREAM_PROTOCOL_VIOLATION` instead.
pub(crate) static UPSTREAM_HEAD_FAILED: Signal = Signal::new();

/// Splice clients demoted to ordinary cached-file delivery.
pub(crate) static CLIENTS_DEMOTED: Counter = Counter::new();

/// Zero-copy download pipes the kernel refused to grow to 1 MiB (`EPERM`
/// from `F_SETPIPE_SZ`): the service user's pipe quota
/// (`fs.pipe-user-pages-soft`) is exhausted, or `fs.pipe-max-size` is below
/// 1 MiB. Counted per pipe, two per plain-HTTP download; each refused pipe
/// keeps its small default size, so its download flushes to the cache every
/// few KiB instead of every MiB.
pub(crate) static PIPE_RESIZE_REFUSED: Signal = Signal::new();

/// Total body bytes pulled from upstream (sum across all backends).
pub(crate) static BYTES_DOWNLOADED_UPSTREAM: Accumulator = Accumulator::new();

/// Requests that attached to an in-flight download instead of fetching anew.
/// High values relative to `CACHE_MISSES + VOLATILE_REFETCHED` mean
/// coalescing carries real traffic. Every late joiner is also counted in its
/// flavor's miss bucket: `CACHE_MISSES` for a permanent resource,
/// `VOLATILE_REFETCHED` for a volatile one.
pub(crate) static LATE_JOINERS_TOTAL: Counter = Counter::new();
/// Most late joiners any single download has had: the entry's joiner count
/// only grows while the download lives (a joiner that leaves early is not
/// subtracted), so this is joiners per download, not joiners at once.
pub(crate) static LATE_JOINER_PEAK_PER_DOWNLOAD: Peak = Peak::new();

/// Splice upstream pool: connection reused / opened fresh.
pub(crate) static POOL_REUSED: Counter = Counter::new();
pub(crate) static POOL_NEW: Counter = Counter::new();

/// Why a checkout missed: no entry for this host (raise
/// `UPSTREAM_POOL_MAX_IDLE_PER_HOST`), every entry had been closed by the peer (lower
/// `POOL_IDLE_TIMEOUT`), or the request on the live entry failed in flight
/// with a transport error (a protocol violation on it is a 502, not a miss).
pub(crate) static POOL_MISS_EMPTY: Counter = Counter::new();
pub(crate) static POOL_MISS_DEAD: Counter = Counter::new();
pub(crate) static POOL_MISS_FAILED: Counter = Counter::new();
/// Pool miss: no cached scheme for the mirror, so no `(host, port, is_tls)`
/// key existed to look up by — the pool was bypassed entirely. Distinct
/// from `POOL_MISS_EMPTY`, which is a lookup that returned no entry.
pub(crate) static POOL_MISS_NO_SCHEME: Counter = Counter::new();

/// Pool returns where the per-host slot was full and the oldest entry was
/// evicted (raise `UPSTREAM_POOL_MAX_IDLE_PER_HOST` if recurring).
pub(crate) static POOL_RETURN_EVICTED: Counter = Counter::new();

/// Downloads rejected by `CacheQuota::try_acquire` (would exceed `disk_quota`
/// or leave less than `min_disk_free` on the cache filesystem).
pub(crate) static DOWNLOAD_REJECTED_QUOTA: Signal = Signal::new();
/// Downloads rejected because the upstream-declared object size exceeded the
/// configured `max_object_size`.
pub(crate) static DOWNLOAD_REJECTED_OVERSIZE: Signal = Signal::new();
/// Requests rejected with 503 because the resource recently failed checksum
/// verification and is inside its backoff window (upstream not contacted).
pub(crate) static DOWNLOAD_REJECTED_VERIFY_THROTTLE: Signal = Signal::new();

/// Permanent-file cache lookup found a usable file. The sum of its parts:
/// `CACHE_HITS == PACKAGE_HITS + BYHASH_HITS` (the parent is bumped first,
/// both by `ConnectionDetails::count_lookup`, the one lookup-site helper).
pub(crate) static CACHE_HITS: Counter = Counter::new();
/// Permanent-file cache lookup needed a fetch (volatile cases use
/// VOLATILE_*). `CACHE_MISSES == PACKAGE_MISSES + BYHASH_MISSES`, bumped like
/// `CACHE_HITS`.
pub(crate) static CACHE_MISSES: Counter = Counter::new();
/// Part of `CACHE_HITS`: a `.deb` (structured or flat pool) served from the
/// cache.
pub(crate) static PACKAGE_HITS: Counter = Counter::new();
/// Part of `CACHE_MISSES`: a `.deb` fetched upstream or joined in flight.
/// Clients naming one archive under different mirror names miss each
/// other's copies; `aliases` maps them onto one.
pub(crate) static PACKAGE_MISSES: Counter = Counter::new();
/// Part of `CACHE_HITS`: a content-addressed by-hash index served from the
/// cache.
pub(crate) static BYHASH_HITS: Counter = Counter::new();
/// Part of `CACHE_MISSES`: a by-hash index fetched upstream or joined in
/// flight.
pub(crate) static BYHASH_MISSES: Counter = Counter::new();

/// Per-delivery-mechanism triples. For each mechanism `X`, `REQUESTS_X`
/// counts responses that started down that path (bumped before the
/// response head is written, so a failed head write counts as started) and
/// `SERVED_X` the subset that completed; both belong to the backend that
/// answered the request. `BYTES_SERVED_X` (above) counts the bytes the
/// mechanism itself shipped, which is not always the same request set: a
/// splice request's demoted tail and resumed prefix are `sendfile(2)` bytes
/// (see `BYTES_SERVED_SENDFILE`). `SERVED_TOTAL` is the sum of the
/// `SERVED_X` plus `SERVED_WEBUI`.
pub(crate) static REQUESTS_SENDFILE: Counter = Counter::new();
pub(crate) static SERVED_SENDFILE: Counter = Counter::new();
pub(crate) static REQUESTS_SPLICE: Counter = Counter::new();
pub(crate) static SERVED_SPLICE: Counter = Counter::new();
pub(crate) static REQUESTS_COPY: Counter = Counter::new();
pub(crate) static SERVED_COPY: Counter = Counter::new();
/// `ChannelBody`: streamed from an in-flight download, to a late joiner or
/// to the hyper client that started it (`LATE_JOINERS_TOTAL` counts the
/// joiners alone).
pub(crate) static REQUESTS_CHANNEL: Counter = Counter::new();
pub(crate) static SERVED_CHANNEL: Counter = Counter::new();

/// Mirror responses that violated the HTTP contract, counted once each where
/// the violation is detected: an unparsable or oversized response head;
/// framing headers that could be read two ways (`resolve_body_framing`);
/// a body that over- or undershot the announced `Content-Length`, or
/// chunked framing errors; body bytes behind the head beyond the declared
/// length (`InconsistentBodyFraming`, including stray bytes after a 304);
/// a 1xx interim head where a final one was due; a resumed 206 whose
/// `Content-Length` disagrees with its `Content-Range` span; a missing
/// `Content-Length` on a permanent-file fetch, or `Content-Length: 0` on
/// any cached fetch; or `206 Partial Content` returned without a Range
/// request. A `Content-Range` that does
/// not match the resume offset is not counted: it is a `ResumeAnomaly`,
/// answered by discarding the partial and refetching. Nor is a violation
/// in the body of a response the proxy abandoned and only drains for
/// connection reuse (splice's `UpstreamExchange::dispose`): that connection
/// is just not pooled.
pub(crate) static UPSTREAM_PROTOCOL_VIOLATION: Signal = Signal::new();

/// Responses exceeding a local body buffering or relay limit. The response
/// may be valid HTTP; these are not protocol faults. A body too large to
/// drain for connection reuse is not counted: that connection is just not
/// pooled.
pub(crate) static UPSTREAM_BODY_LIMIT: Signal = Signal::new();

/// Mirror responses that returned `206 Partial Content` for a request the
/// proxy issued without a `Range:` header. Treating these as 200-equivalent
/// would write the partial body into the cache at offset 0 and mark the
/// file complete at the partial length, so the proxy rejects them with 502
/// instead. A specific telemetry slice of `UPSTREAM_PROTOCOL_VIOLATION`
/// (both counters are bumped together at the reject site).
pub(crate) static UPSTREAM_UNSOLICITED_206: Signal = Signal::new();

/// Hyper-backend upstream errors observed *after* response headers were
/// received, while streaming the body: a reset, a read or TLS failure, a
/// framing error. A body the upstream ended before its announced length is
/// an `UPSTREAM_PROTOCOL_VIOLATION` instead, as in splice, and not counted
/// here.
pub(crate) static UPSTREAM_HYPER_BODY_ERR: Signal = Signal::new();

/// Local cache I/O failures: any cached-file syscall (write/flush/read/
/// rename/create/stat/open/seek) that fails, regardless of whether a
/// 5xx is returned to the client. Distinct from `CACHE_SIZE_CORRUPTION`,
/// which is specific to on-disk size accounting drift.
pub(crate) static CACHE_IO_FAILURE: Signal = Signal::new();

/// Cache entries observed to be non-regular non-directory files (FIFO,
/// socket, device, symlink).  Bumped by serving paths (which then return
/// 5xx), download paths (which abort the download) -- including an open the
/// entry itself failed: a symlink `O_NOFOLLOW` refuses (`ELOOP`), a
/// directory opened for writing (`EISDIR`), a socket (`ENXIO`), classified
/// by `fs_open::count_cache_failure` -- and every directory
/// walk (`cache_walk.rs`, on sight): the startup scan and the dashboard
/// leave such an entry in place, cleanup unlinks it wherever it walks
/// (pool / flat / `dists/` / by-hash / `tmp/`).
/// A non-zero count indicates either a hostile filesystem or a
/// misconfigured cache directory and is worth operator attention.
/// Disjoint from `CACHE_IO_FAILURE`: a non-regular-file detection is
/// reported here only.  If a subsequent removal attempt's syscall itself
/// fails, that is reported separately under `CACHE_IO_FAILURE`.  Unexpected
/// directories are tracked separately under `CACHE_DIRECTORY_UNEXPECTED`
/// when detected on dedicated directory-classification paths; however a
/// number of serving paths (`main.rs`, `sendfile_conn.rs`, `splice/`)
/// and TOCTOU-safe sweep paths in the `cleanup/` submodule still bump
/// `CACHE_NON_REGULAR` for directories encountered at file locations.
/// Treat the counter as "any non-regular entry where a regular file was
/// expected"; if you need the strict FIFO/socket/device/symlink slice,
/// filter at the call site.
pub(crate) static CACHE_NON_REGULAR: Signal = Signal::new();

/// Cache entries observed to be directories in places where the cache
/// layout does not allow one (an unknown host dir at the cache root, a
/// non-layout dir in a mirror dir, anything in a pool / by-hash leaf).
/// Bumped through `cache_walk::Entry::report_unexpected` by the walk that
/// knows the layout; cleanup leaves the directory in place and emits a
/// warn — the cache layout has no recursive-remove semantics there and
/// a directory typically indicates operator action (e.g. a `mv` into the
/// cache tree).  The single exception is `tmp/`, where stray directories
/// are recursively removed once aged; the bump there fires on every
/// cycle the directory is seen, like everywhere else.  Distinct from
/// `CACHE_NON_REGULAR` because the operator response differs: a stray
/// directory is usually benign-but-wasteful; a stray FIFO/socket/symlink
/// is a security-relevant tampering signal.
pub(crate) static CACHE_DIRECTORY_UNEXPECTED: Signal = Signal::new();

/// Cache entries observed to be regular files where the layout does not
/// allow one: at the cache root (whose only legitimate children are
/// alias-resolved host dirs), a non-deb file directly in a mirror dir,
/// or a non-UTF-8-named file cleanup can never match against an index.
/// Bumped through `cache_walk::Entry::report_unexpected`; the file is
/// left in place with a warn — like a stray directory, this is typically
/// an operator artefact (e.g. a hand-placed `.txt` note) rather than a
/// tampering signal.
/// Distinct from `CACHE_NON_REGULAR` (FIFO/socket/device/symlink, which
/// are security-relevant) and `CACHE_DIRECTORY_UNEXPECTED` (the
/// directory-shaped counterpart inside mirror subtrees).
pub(crate) static CACHE_UNEXPECTED_REGULAR: Signal = Signal::new();

/// Bytes copied client → upstream through the CONNECT tunnel, including a
/// payload pipelined behind the `CONNECT` head (a TLS `ClientHello`).
///
/// Counted on the client side as the relay moves them
/// (`connect_tunnel::copy_bidirectional_idle`) and published when the tunnel
/// ends, however it ends: cleanly, idle-closed or failed. After a transfer
/// error it may include up to one buffer read from the client but never
/// delivered upstream.
pub(crate) static BYTES_TUNNELED_CLIENT_TO_UPSTREAM: Accumulator = Accumulator::new();
/// Bytes copied upstream → client through the CONNECT tunnel; counted and
/// published like `BYTES_TUNNELED_CLIENT_TO_UPSTREAM` (bytes the client
/// socket accepted), whichever way the tunnel ends.
pub(crate) static BYTES_TUNNELED_UPSTREAM_TO_CLIENT: Accumulator = Accumulator::new();

/// HTTP timeout firings: upstream read (response headers and body).
///
/// Splice path: bumped when the per-read deadline fires anywhere in the
/// upstream read flow — `read_upstream_response_headers`, the body
/// splice loops (TCP and userspace-TLS variants), the chunked / EOF / volatile
/// buffered-download readers, the error-response forwarder, and
/// `read_body_to_vec_until_eof` / `read_dechunk_body_to_vec`. The name
/// is historical; coverage is "upstream read deadline fired," whether
/// the bytes were headers or body. Hyper path: bumped when
/// `hyper-timeout`'s read/write timeout surfaces as a hyper transport
/// error during request/response header exchange or body streaming
/// (detected by walking the error source chain for an
/// `io::ErrorKind::TimedOut`).
pub(crate) static HTTP_TIMEOUT_UPSTREAM_READ: Signal = Signal::new();
/// HTTP timeout firings: upstream TCP/TLS handshake, counted per attempt
/// (a request whose retries all time out counts each of them, and once in
/// `UPSTREAM_CONNECT_FAILED`).
///
/// Splice path: bumped when `tcp_connect` or the TLS handshake exceeds
/// the configured timeout. Hyper path: bumped when `hyper-timeout`'s
/// connect timeout fires (detected by walking the connect error source
/// chain for an `io::ErrorKind::TimedOut`). Also bumped when a CONNECT
/// tunnel's upstream dial times out, in both backends.
pub(crate) static HTTP_TIMEOUT_UPSTREAM_CONNECT: Signal = Signal::new();
/// HTTP timeout firings: client failed to send request headers in time
/// (slow-loris-shaped, or a stalled client between keep-alive requests).
///
/// Scope: only updated by the sendfile backend's `read_request_headers`.
/// In `cfg(not(feature = "sendfile"))` builds (non-default) the hyper path's
/// `header_read_timeout` is configured from `client_idle_timeout` and does
/// fire on idle/slow-header clients, but it is not counted here -- it logs at
/// debug level instead, so this counter stays at 0 on those builds.
pub(crate) static HTTP_TIMEOUT_CLIENT_HEADER: Counter = Counter::new();
/// HTTP timeout firings: client failed to drain the response body within
/// `http_timeout` (slow reader, dropped link). A client falling below
/// `min_download_rate` is not a timeout: it counts only in
/// `RATE_LIMIT_CLIENT`.
///
/// Scope: response-body writes via `write_all_to_stream(.., WritePhase::Body)`,
/// every rated-write helper (`write_all_to_stream_rated{,_counted}`,
/// `wait_socket_rated`), and the sendfile chunk loop. Hyper's internal-timer
/// body delivery is not routed through these helpers and is not counted
/// here. Header-write timeouts are tracked separately in
/// `HTTP_TIMEOUT_CLIENT_HEADER_WRITE`.
pub(crate) static HTTP_TIMEOUT_CLIENT_BODY: Signal = Signal::new();
/// HTTP timeout firings: client failed to drain a response-header (or other
/// small fixed control) write in time. Distinct from
/// `HTTP_TIMEOUT_CLIENT_HEADER`, which counts request-header *reads* that
/// stalled before any request was parsed.
///
/// Scope: client writes of response heads and small proxy-generated
/// responses (304/416/error responses, the tunnel's `200`), through
/// `write_all_to_stream(.., WritePhase::Header)` and
/// `write_all_to_stream_msg_more`.
pub(crate) static HTTP_TIMEOUT_CLIENT_HEADER_WRITE: Counter = Counter::new();

/// `max_upstream_downloads` saturation episodes — debounced (latched at cap,
/// cleared when the active set drains to zero). Climbing → recurring saturation.
pub(crate) static UPSTREAM_DOWNLOAD_CAP_TRANSITIONS: Signal = Signal::new();

/// Requests rejected (503) because the active-download set was already at the cap.
pub(crate) static UPSTREAM_DOWNLOAD_REJECTED_CAP: Signal = Signal::new();
/// New originations admitted against `max_upstream_downloads` (one per
/// `UpstreamSlot` minted); with `UPSTREAM_DOWNLOAD_REJECTED_CAP` the share of
/// originations the cap refused. Late joiners open no slot and count in
/// neither.
pub(crate) static UPSTREAM_DOWNLOADS_ADMITTED: Counter = Counter::new();
/// Time the upstream slots spent at `max_upstream_downloads`.
pub(crate) static UPSTREAM_DOWNLOAD_CAP_CLOCK: CapClock = CapClock::new();

/// Uncached passthrough requests refused (503) because
/// `max_passthrough_relays` relays were already active, bumped by
/// `passthrough_limiter::admit` for every backend.
pub(crate) static PASSTHROUGH_REJECTED_CAP: Signal = Signal::new();
/// Highest number of concurrent passthrough relays since startup, sampled on
/// every successful admission, whether or not `max_passthrough_relays` caps
/// them (a refused relay never counted as active).
pub(crate) static PASSTHROUGH_ACTIVE_PEAK: Peak = Peak::new();
/// Passthrough relays admitted (`passthrough_limiter::admit`), capped or
/// not; with `PASSTHROUGH_REJECTED_CAP` the share the cap refused.
pub(crate) static PASSTHROUGH_ADMITTED: Counter = Counter::new();
/// Time the passthrough relays spent at `max_passthrough_relays`.
pub(crate) static PASSTHROUGH_CAP_CLOCK: CapClock = CapClock::new();

/// Upstream connect attempts past a request's first, in both backends:
/// every backoff retry (`upstream_retry::Backoff::next_retry`) and every
/// Auto-mode dial of the original scheme after a failed HTTPS probe
/// (hyper's revert iteration, splice's fallback dial in
/// `connect_upstream`).
pub(crate) static UPSTREAM_RETRIES: Counter = Counter::new();

/// Log-ring evictions: the oldest entry dropped for a new one once the
/// in-memory ring (`logstore_capacity` entries) is full. Non-zero on any
/// daemon that has logged more than the ring holds, so it is no alarm;
/// only its rate says how far back the web log page reaches.
pub(crate) static LOGSTORE_EVICTIONS: Counter = Counter::new();

/// Peak cache disk-quota utilization in basis points (10000 = 100%). Not
/// clamped: an over-quota accounted size reads above 10000, like the
/// current utilization shown beside it. Only meaningful when `disk_quota`
/// is configured; otherwise stays at 0.
pub(crate) static CACHE_QUOTA_UTIL_PEAK_BPS: Peak = Peak::new();

/// HTTPS upgrade attempted on an HTTP request (Auto / uncached scheme).
/// Every attempt resolves to exactly one of `HTTPS_UPGRADE_SUCCEEDED`,
/// `HTTPS_UPGRADE_REVERTED`, or `HTTPS_UPGRADE_FAILED`, so the identity
/// `ATTEMPTED == SUCCEEDED + REVERTED + FAILED` holds. Both the hyper and
/// splice backends write these counters; the identity holds per-backend and
/// in aggregate, though the mechanism differs (see each subset below).
pub(crate) static HTTPS_UPGRADE_ATTEMPTED: Counter = Counter::new();
/// HTTPS upgrade succeeded. hyper: bumped on the first successful upstream
/// response (any status) after the upgrade flag was set. The host's
/// https scheme is also cached in this same code path when no entry
/// exists yet, but the metric fires before the cache-write check, so a
/// response with an unsupported scheme or a non-2xx status still
/// counts as a success here. splice: bumped at connect/handshake success
/// (before the response headers are read), so a later header-read failure
/// is not re-counted as `HTTPS_UPGRADE_FAILED`.
pub(crate) static HTTPS_UPGRADE_SUCCEEDED: Counter = Counter::new();
/// HTTPS upgrade reverted: the upgrade was abandoned in favour of the
/// original scheme (the request may still succeed via it; this counter only
/// marks that the upgrade attempt was abandoned, not that the request as a
/// whole failed). hyper: Auto-mode gave up after
/// `HTTPS_UPGRADE_REVERT_AFTER_ATTEMPTS` connect failures and reverted.
/// splice: the one-shot HTTPS-then-HTTP fallback in `connect_upstream`
/// connected via HTTP for an Auto-mode upgrade attempt.
pub(crate) static HTTPS_UPGRADE_REVERTED: Counter = Counter::new();
/// HTTPS upgrade failed terminally: the upgrade attempt resolved to neither
/// success nor revert. hyper: Always-mode exhausts the connect-retry budget
/// (attempt cap or `upstream_retry_budget`; Auto-mode would normally have
/// reverted first, see `HTTPS_UPGRADE_REVERTED`, unless the wall-clock budget
/// ran out before the third attempt), or any mode hits a non-connect transport
/// error (e.g. read timeout, request framing) that terminates the request
/// without retry. splice: the connect retry loop exhausts its budget with both
/// schemes failing (including a both-schemes-dead Auto host, which splice
/// counts here where hyper would count `HTTPS_UPGRADE_REVERTED`).
pub(crate) static HTTPS_UPGRADE_FAILED: Counter = Counter::new();

/// Scheme-cache entries purged after the connect-retry budget was exhausted.
pub(crate) static SCHEME_CACHE_REMOVED: Counter = Counter::new();

/// Database operations that returned an error. Any non-zero value
/// indicates `SQLite` trouble worth investigating.
pub(crate) static DB_OPERATION_FAILED: Signal = Signal::new();

/// Registered downloads that ended aborted instead of committed: any failed
/// download (an upstream failure in any phase -- connect, head, body,
/// rate, protocol, body limit -- a cache I/O failure, an internal failure,
/// a barrier dropped without a verdict) and a finished download its commit
/// discarded (checksum mismatch, verify or rename failure). A download the
/// originator declined (relayed status, quota, throttle, ...) is not an
/// abort.
pub(crate) static DOWNLOADS_ABORTED: Signal = Signal::new();
/// `DOWNLOADS_ABORTED` split by cause; every abort bumps the parent and
/// exactly one of these (`guards::count_abort`), so they sum to it.
/// The mirror failed the transfer (`DownloadFailure::Upstream`).
pub(crate) static DOWNLOADS_ABORTED_UPSTREAM: Signal = Signal::new();
/// A local cache syscall failed (`DownloadFailure::Cache`), or the commit
/// could not read back or rename the finished file.
pub(crate) static DOWNLOADS_ABORTED_CACHE: Signal = Signal::new();
/// The commit discarded a complete body whose digest did not match.
pub(crate) static DOWNLOADS_ABORTED_CHECKSUM: Signal = Signal::new();
/// An internal transfer failure (`DownloadFailure::Internal`): a pipe or
/// task broke on this side.
pub(crate) static DOWNLOADS_ABORTED_INTERNAL: Signal = Signal::new();
/// The download's barrier was dropped without a verdict
/// (`DownloadFailure::Cancelled`): its task was cancelled, typically
/// because every client it served went away.
pub(crate) static DOWNLOADS_ABORTED_CANCELLED: Signal = Signal::new();
/// Registered downloads the originator ended without fetching a body
/// (`InitBarrier::decline`): the upstream status is relayed uncached, the
/// planner refused the answer, the disk quota or the verify throttle
/// refused it, the passthrough cap refused the relay, a buffered volatile
/// body came back empty. Not an abort: no transfer broke mid-way. A refusal by `max_upstream_downloads` never registers a download
/// and counts only in `UPSTREAM_DOWNLOAD_REJECTED_CAP`.
pub(crate) static DOWNLOADS_DECLINED: Counter = Counter::new();
/// Downloads that found their `.partial` path still claimed by an earlier
/// download of the same file (`partial_claim`) and wrote into a scratch file
/// instead of resuming it.
pub(crate) static PARTIAL_CLAIM_CONTENDED: Counter = Counter::new();

/// Orphaned partials at the last completed cache scan (startup, then after
/// every cleanup): `.partial`s in a `tmp/` no running download claimed --
/// the resume state of downloads that failed or were abandoned, counted in
/// `disk_quota` until cleanup reaps them. Their accounted bytes, and when
/// the scan finished (Unix seconds, 0 before the first; set last, like
/// `LAST_CLEANUP_FINISHED_AT`).
pub(crate) static ORPHANED_PARTIAL_FILES: StateU64 = StateU64::new();
pub(crate) static ORPHANED_PARTIAL_BYTES: StateU64 = StateU64::new();
pub(crate) static ORPHANED_PARTIALS_SCANNED_AT: StateU64 = StateU64::new();

/// Cache-size reconciliation events with a non-zero on-disk delta.
pub(crate) static RECONCILE_EVENTS: Signal = Signal::new();
/// Total absolute bytes corrected by reconciliation events.
pub(crate) static RECONCILE_BYTES_REPAIRED: Accumulator = Accumulator::new();

/// `cache_quota.rs` accounting-integrity errors ("Cache-quota reconcile
/// overflowed", "Cache-size accounting overflowed on add" / "underflowed on
/// subtract") — any non-zero is a bug signal.
pub(crate) static CACHE_SIZE_CORRUPTION: Signal = Signal::new();

/// Authorization rejection: client request denied by the mirror allowlist.
pub(crate) static AUTHZ_REJECTED_MIRROR: Counter = Counter::new();
/// Authorization rejection: client request denied by the client allowlist.
pub(crate) static AUTHZ_REJECTED_CLIENT: Counter = Counter::new();
/// Authorization rejection: HTTPS-tunnel CONNECT denied by the tunnel-mirror list.
pub(crate) static AUTHZ_REJECTED_TUNNEL_MIRROR: Counter = Counter::new();
/// Authorization rejection: web-interface access denied by the webif-client
/// allowlist (`allowed_webif_clients`, falling back to `allowed_proxy_clients`).
pub(crate) static AUTHZ_REJECTED_WEBUI: Counter = Counter::new();
/// Authorization rejection: web-interface request refused with 421 because
/// its `Host` names none of the proxy's own names (DNS-rebinding guard).
pub(crate) static AUTHZ_REJECTED_WEBUI_HOST: Signal = Signal::new();

/// Transfers cancelled because the upstream min-rate threshold was not met.
pub(crate) static RATE_LIMIT_UPSTREAM: Signal = Signal::new();
/// Transfers cancelled because the client min-rate threshold was not met.
pub(crate) static RATE_LIMIT_CLIENT: Signal = Signal::new();

/// `DatabaseCommand` enqueues via `send_db_command` (every send is counted).
pub(crate) static DB_COMMANDS_SENT: Counter = Counter::new();
/// Peak observed DB-command channel depth at send/receive boundaries.
pub(crate) static DB_QUEUE_DEPTH_PEAK: Peak = Peak::new();
/// Sends that observed a fully-saturated channel. The two bump sites differ
/// in what follows: the async `send_db_command` samples `capacity() == 0`
/// *before* sending and may then complete without ever parking, while
/// `send_db_command_nonblocking` bumps only when `try_send` actually returned
/// `Full` and it had to spill the command onto a task. So this counts
/// observations of saturation, not waits.
pub(crate) static DB_QUEUE_FULL_WAITS: Signal = Signal::new();
/// Debounced `DB_QUEUE_FULL_WAITS` — counts each saturation episode once
/// (latched until the channel drains fully to empty).
pub(crate) static DB_QUEUE_FULL_TRANSITIONS: Signal = Signal::new();
/// Time the DB command channel spent full (`db_channel_capacity`), so that
/// request paths waited on database writes. A span starts when a sender finds
/// the channel full (before an async send, or a `try_send` refused as `Full`);
/// a send that merely fills the final slot starts none. It ends at the first
/// later observation that finds room: after a send, a receive, a cancelled
/// send or closure. Observations and clock transitions are serialized; a
/// brief drain between observations can be missed. Closure ends the span
/// even while buffered commands drain.
pub(crate) static DB_QUEUE_CAP_CLOCK: CapClock = CapClock::new();
/// Commands dropped because the DB task channel was closed (graceful shutdown
/// or unexpected receiver death). Bumped instead of panicking so request tasks
/// can finish their response after the DB drain begins.
pub(crate) static DB_COMMANDS_DROPPED_SHUTDOWN: Counter = Counter::new();

/// Batch flushes triggered because the buffered-command count reached
/// `db_batch_flush_max_count`. Under sustained load this should dominate
/// `DB_BATCH_FLUSHES_BY_TIME`.
pub(crate) static DB_BATCH_FLUSHES_BY_SIZE: Counter = Counter::new();
/// Batch flushes triggered by the periodic interval tick. Dominant during
/// idle hours; ratio with `_BY_SIZE` indicates whether the size threshold
/// is well-tuned.
pub(crate) static DB_BATCH_FLUSHES_BY_TIME: Counter = Counter::new();
/// Batch flushes performed during graceful shutdown drain.
pub(crate) static DB_BATCH_FLUSHES_ON_SHUTDOWN: Counter = Counter::new();
/// Peak number of buffered commands attempted in a single batch flush.
/// Counts attempts, including partially-failed ones; pair with
/// `DB_OPERATION_FAILED` to tell the two apart.
pub(crate) static DB_BATCH_SIZE_PEAK: Peak = Peak::new();
/// Mirror-id cache hits: the `(host, port, path)` lookup found an existing id
/// without touching the database.
pub(crate) static DB_MIRROR_CACHE_HITS: Counter = Counter::new();
/// Mirror-id cache misses: one synchronous upsert against `mirrors_v2` was
/// performed to obtain the id. After warmup this should grow only when a
/// previously-unseen mirror appears.
pub(crate) static DB_MIRROR_CACHE_MISSES: Counter = Counter::new();
/// Total `mirrors_v2.last_seen` rows updated by the periodic flush task.
pub(crate) static DB_MIRROR_LAST_SEEN_FLUSHED: Accumulator = Accumulator::new();
/// Current size of the in-memory mirror-id cache (entries hydrated at startup
/// plus newly observed mirrors). Entries are never evicted, so this only grows.
pub(crate) static DB_MIRROR_CACHE_ENTRIES: StateU64 = StateU64::new();

/// Total cache files evicted across all cleanup runs.
pub(crate) static CLEANUP_EVICTIONS: Accumulator = Accumulator::new();
/// Total bytes reclaimed across all cleanup runs, each file counted as its
/// `cache_quota::accounted_size`.
pub(crate) static CLEANUP_BYTES_RECLAIMED: Accumulator = Accumulator::new();
/// By-hash files evicted because their digest was absent from the mirror's
/// current `Release`/`InRelease` set (reference-based reclaim). A subset of
/// `CLEANUP_EVICTIONS`; the remainder of by-hash evictions are aged out by the
/// `byhash_retention_days` backstop when no current Release could be read.
pub(crate) static CLEANUP_BYHASH_UNREFERENCED: Accumulator = Accumulator::new();
/// Cache files removed by cleanup because their content hash did not match the
/// value advertised in the upstream Packages stanza. A non-zero counter
/// indicates either disk corruption, an upstream mirror returning a different
/// build than its index claims, or a stale cache file whose origin re-issued
/// the same `Filename:` under a different content.
pub(crate) static CLEANUP_CHECKSUM_MISMATCHES: Signal = Signal::new();
/// Cleanup digest verifications skipped because the file carries a valid
/// verified-marker xattr from an earlier cycle (same inode, size, algorithm
/// and expected digest) — the daily re-hash then scales with churn instead
/// of total cache size.
pub(crate) static CLEANUP_CHECKSUM_SKIPS: Counter = Counter::new();

/// Last cleanup run of this process: when it finished (Unix seconds; 0
/// before the first run since start). Set last, after the trio below, so a
/// reader that finds it set finds them set too. The persisted counterpart
/// is the mirrors' `last_cleanup` column, which survives restarts.
pub(crate) static LAST_CLEANUP_FINISHED_AT: StateU64 = StateU64::new();
/// Last cleanup run: duration in seconds (atomically updated; readers may
/// observe a transient mix across the trio between updates).
pub(crate) static LAST_CLEANUP_DURATION_SECS: StateU64 = StateU64::new();
/// Last cleanup run: number of files removed.
pub(crate) static LAST_CLEANUP_FILES_REMOVED: StateU64 = StateU64::new();
/// Last cleanup run: bytes reclaimed (in `cache_quota::accounted_size` units).
pub(crate) static LAST_CLEANUP_BYTES_RECLAIMED: StateU64 = StateU64::new();

/// Record a client response status code into the matching class counter plus the
/// fine-grained bucket for statuses we track individually. The class is
/// bumped first, so a reader that loads the codes before their class never
/// sees the codes exceed it.
pub(crate) fn record_client_status(status: StatusCode) {
    match status.as_u16() {
        200..=299 => CLIENT_STATUS_2XX.increment(),
        300..=399 => CLIENT_STATUS_3XX.increment(),
        400..=499 => CLIENT_STATUS_4XX.increment(),
        500..=599 => CLIENT_STATUS_5XX.increment(),
        _ => CLIENT_STATUS_OTHER.increment(),
    }

    match status {
        StatusCode::OK => CLIENT_STATUS_200.increment(),
        StatusCode::PARTIAL_CONTENT => CLIENT_STATUS_206.increment(),
        StatusCode::NOT_MODIFIED => CLIENT_STATUS_304.increment(),
        StatusCode::GONE => CLIENT_STATUS_410.increment(),
        StatusCode::RANGE_NOT_SATISFIABLE => CLIENT_STATUS_416.increment(),
        StatusCode::INTERNAL_SERVER_ERROR => CLIENT_STATUS_500.increment(),
        StatusCode::BAD_GATEWAY => CLIENT_STATUS_502.increment(),
        StatusCode::SERVICE_UNAVAILABLE => CLIENT_STATUS_503.increment(),
        _ => {}
    }
}

/// Record an upstream response status code. Tracks status-class buckets and
/// the individually-tracked codes (200/206/301/302/304/307/308) independently
/// from the client-side `record_client_status`, class first like it.
pub(crate) fn record_upstream_status(status: StatusCode) {
    match status.as_u16() {
        200..=299 => UPSTREAM_STATUS_2XX.increment(),
        300..=399 => UPSTREAM_STATUS_3XX.increment(),
        400..=499 => UPSTREAM_STATUS_4XX.increment(),
        500..=599 => UPSTREAM_STATUS_5XX.increment(),
        _ => UPSTREAM_STATUS_OTHER.increment(),
    }

    match status {
        StatusCode::OK => UPSTREAM_STATUS_200.increment(),
        StatusCode::PARTIAL_CONTENT => UPSTREAM_STATUS_206.increment(),
        StatusCode::MOVED_PERMANENTLY => UPSTREAM_STATUS_301.increment(),
        StatusCode::FOUND => UPSTREAM_STATUS_302.increment(),
        StatusCode::NOT_MODIFIED => UPSTREAM_STATUS_304.increment(),
        StatusCode::TEMPORARY_REDIRECT => UPSTREAM_STATUS_307.increment(),
        StatusCode::PERMANENT_REDIRECT => UPSTREAM_STATUS_308.increment(),
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use http::StatusCode;

    use super::*;

    #[test]
    fn a_cap_clock_accumulates_spans_at_the_cap() {
        let clock = CapClock::new();
        assert_eq!(clock.total_at(100), std::time::Duration::ZERO);
        clock.enter_at(1_000);
        // Idempotent: a second admission at the cap keeps the span's start.
        clock.enter_at(5_000);
        assert!(clock.is_at_cap());
        clock.leave_at(9_000);
        clock.leave_at(9_500);
        assert!(!clock.is_at_cap());
        let first: std::time::Duration = coarsetime::Duration::from_ticks(8_000).into();
        assert_eq!(clock.total_at(20_000), first);
        // A running span counts up to "now".
        clock.enter_at(30_000);
        let running: std::time::Duration = coarsetime::Duration::from_ticks(8_000 + 2_000).into();
        assert_eq!(clock.total_at(32_000), running);
    }

    /// Each code a row is shown for lands in its row and its class; other
    /// tests bump the same globals concurrently, so only growth is asserted.
    #[test]
    fn status_codes_land_in_their_row_and_class() {
        let (u206, u2xx) = (UPSTREAM_STATUS_206.get(), UPSTREAM_STATUS_2XX.get());
        record_upstream_status(StatusCode::PARTIAL_CONTENT);
        assert!(UPSTREAM_STATUS_206.get() > u206);
        assert!(UPSTREAM_STATUS_2XX.get() > u2xx);

        for (status, row) in [
            (StatusCode::INTERNAL_SERVER_ERROR, &CLIENT_STATUS_500),
            (StatusCode::BAD_GATEWAY, &CLIENT_STATUS_502),
            (StatusCode::SERVICE_UNAVAILABLE, &CLIENT_STATUS_503),
        ] {
            let (code, class) = (row.get(), CLIENT_STATUS_5XX.get());
            record_client_status(status);
            assert!(row.get() > code, "{status}");
            assert!(CLIENT_STATUS_5XX.get() > class, "{status}");
            assert!(row.last().is_some(), "{status}");
        }
    }

    #[test]
    fn a_signal_is_unstamped_until_its_first_bump() {
        let signal = Signal::new();
        assert_eq!(signal.get(), 0);
        assert_eq!(signal.last(), None);
    }

    #[test]
    fn a_signal_bump_counts_and_stamps_the_wall_clock() {
        let signal = Signal::new();
        let before = coarsetime::Clock::now_since_epoch().as_secs();
        signal.increment();
        signal.increment();
        let after = coarsetime::Clock::now_since_epoch().as_secs();
        assert_eq!(signal.get(), 2);
        let last = signal.last().expect("a bumped signal is stamped");
        // The coarse clock ticks every few milliseconds, so allow the one
        // second the reads above can straddle.
        assert!(
            (before..=after + 1).contains(&last),
            "{before} <= {last} <= {after}"
        );
    }
}
