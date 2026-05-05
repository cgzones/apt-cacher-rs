//! Process-wide runtime counters surfaced by the web interface.
//!
//! All counters are additive and monotonic from process start, except peak
//! values which track the maximum observed since startup.

use std::sync::atomic::{AtomicU64, Ordering};

use http::StatusCode;

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

pub(crate) struct Peak(AtomicU64);

impl Peak {
    #[must_use]
    const fn new() -> Self {
        Self(AtomicU64::new(0))
    }

    pub(crate) fn update(&self, value: u64) {
        let mut current = self.0.load(Ordering::Relaxed);
        while current < value {
            match self
                .0
                .compare_exchange_weak(current, value, Ordering::Relaxed, Ordering::Relaxed)
            {
                Ok(_) => break,
                Err(val) => current = val,
            }
        }
    }

    #[must_use]
    pub(crate) fn get(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }
}

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

/// Total client requests handled.
pub(crate) static REQUESTS_TOTAL: Counter = Counter::new();
/// Web interface requests entering `serve_web_interface`.
pub(crate) static WEBUI_REQUESTS: Counter = Counter::new();
/// TCP connections accepted by the listener.
pub(crate) static CONNECTIONS_ACCEPTED: Counter = Counter::new();

/// Upstream response class buckets (2xx/3xx/4xx/5xx/other).
pub(crate) static UPSTREAM_STATUS_2XX: Counter = Counter::new();
pub(crate) static UPSTREAM_STATUS_3XX: Counter = Counter::new();
pub(crate) static UPSTREAM_STATUS_4XX: Counter = Counter::new();
pub(crate) static UPSTREAM_STATUS_5XX: Counter = Counter::new();
pub(crate) static UPSTREAM_STATUS_OTHER: Counter = Counter::new();

/// Selected upstream status codes tracked individually (200/301/302/304).
pub(crate) static UPSTREAM_STATUS_200: Counter = Counter::new();
pub(crate) static UPSTREAM_STATUS_301: Counter = Counter::new();
pub(crate) static UPSTREAM_STATUS_302: Counter = Counter::new();
pub(crate) static UPSTREAM_STATUS_304: Counter = Counter::new();

/// Client response class buckets (2xx/3xx/4xx/5xx/other).
pub(crate) static CLIENT_STATUS_2XX: Counter = Counter::new();
pub(crate) static CLIENT_STATUS_3XX: Counter = Counter::new();
pub(crate) static CLIENT_STATUS_4XX: Counter = Counter::new();
pub(crate) static CLIENT_STATUS_5XX: Counter = Counter::new();
pub(crate) static CLIENT_STATUS_OTHER: Counter = Counter::new();

/// Selected client status codes tracked individually (200/206/304/410/416).
pub(crate) static CLIENT_STATUS_200: Counter = Counter::new();
pub(crate) static CLIENT_STATUS_206: Counter = Counter::new();
pub(crate) static CLIENT_STATUS_304: Counter = Counter::new();
pub(crate) static CLIENT_STATUS_410: Counter = Counter::new();
pub(crate) static CLIENT_STATUS_416: Counter = Counter::new();

/// Volatile-resource hit served from cache within `VOLATILE_CACHE_MAX_AGE`.
/// Ratio against `VOLATILE_REFETCHED` indicates whether max-age is well-tuned.
pub(crate) static VOLATILE_HIT: Counter = Counter::new();
/// Volatile-resource fetch from upstream (stale on disk or absent).
/// Mutually exclusive with `CACHE_MISSES` (which counts permanent files only).
pub(crate) static VOLATILE_REFETCHED: Counter = Counter::new();
/// Subset of `VOLATILE_REFETCHED`: stale-but-present, upstream returned 304.
pub(crate) static VOLATILE_REFETCHED_UPTODATE: Counter = Counter::new();
/// Subset of `VOLATILE_REFETCHED`: stale-but-present, upstream returned a fresh body.
pub(crate) static VOLATILE_REFETCHED_OUTOFDATE: Counter = Counter::new();

/// Body-write failures attributed to the client (`BrokenPipe` / `ConnectionReset`).
pub(crate) static CLIENT_DISCONNECTED_MID_BODY: Counter = Counter::new();

/// Requests rejected because the path failed safety validation.
pub(crate) static UNSAFE_PATH_REJECTED: Counter = Counter::new();
/// Requests rejected because they targeted a `pdiff` resource.
pub(crate) static PDIFF_REJECTED: Counter = Counter::new();

/// Resources marked uncacheable and tracked in the in-memory ring.
pub(crate) static UNCACHEABLE: Counter = Counter::new();

/// HTTPS CONNECT tunnels accepted.
pub(crate) static TUNNEL_CONNECTS_TOTAL: Counter = Counter::new();
/// CONNECT tunnels rejected by the per-mirror policy list.
pub(crate) static TUNNEL_REJECTED_POLICY: Counter = Counter::new();
/// CONNECT tunnels rejected because the active-tunnel cap was reached.
pub(crate) static TUNNEL_REJECTED_CAPACITY: Counter = Counter::new();

/// Peak concurrent connected clients.
pub(crate) static CONNECTED_CLIENTS_PEAK: Peak = Peak::new();
/// Peak concurrent in-flight upstream downloads.
pub(crate) static ACTIVE_UPSTREAM_DOWNLOADS_PEAK: Peak = Peak::new();
/// Peak concurrent in-flight client-side downloads.
pub(crate) static ACTIVE_CLIENT_DOWNLOADS_PEAK: Peak = Peak::new();

/// Bytes delivered via memory-mapped file I/O.
pub(crate) static BYTES_SERVED_MMAP: Accumulator = Accumulator::new();
/// Bytes delivered via Linux `sendfile(2)` zero-copy.
pub(crate) static BYTES_SERVED_SENDFILE: Accumulator = Accumulator::new();
/// Bytes streamed upstream→client via Linux `splice(2)` zero-copy.
pub(crate) static BYTES_SERVED_SPLICE: Accumulator = Accumulator::new();
/// Bytes delivered via plain userspace read/write copy.
pub(crate) static BYTES_SERVED_COPY: Accumulator = Accumulator::new();
/// Bytes delivered to late joiners via the hyper `ChannelBody` streaming path
/// (`serve_unfinished_file`). Counted at frame-poll time.
pub(crate) static BYTES_SERVED_CHANNEL: Accumulator = Accumulator::new();

/// Bytes proxied uncached. Counted at frame-poll time (no post-write hook in
/// hyper's body model) — slightly overcounts on aborted clients vs. the
/// post-write splice/sendfile counters.
pub(crate) static BYTES_SERVED_PASSTHROUGH: Accumulator = Accumulator::new();
/// Passthrough requests served (companion to `BYTES_SERVED_PASSTHROUGH`).
pub(crate) static REQUESTS_PASSTHROUGH: Counter = Counter::new();

/// Splice-path upstream connect failures (TCP setup).
pub(crate) static UPSTREAM_CONNECT_FAILED: Counter = Counter::new();
/// Splice-path upstream connect failures (TLS handshake).
pub(crate) static UPSTREAM_TLS_FAILED: Counter = Counter::new();

/// Splice clients demoted to ordinary cached-file delivery.
pub(crate) static CLIENTS_DEMOTED: Counter = Counter::new();

/// Total body bytes pulled from upstream (sum across all backends).
pub(crate) static BYTES_DOWNLOADED_UPSTREAM: Accumulator = Accumulator::new();

/// Requests that attached to an in-flight download instead of fetching anew.
/// High values relative to `CACHE_MISSES` mean coalescing carries real traffic.
pub(crate) static LATE_JOINERS_TOTAL: Counter = Counter::new();
/// Peak concurrent late joiners attached to a single in-flight download.
pub(crate) static LATE_JOINER_PEAK_PER_DOWNLOAD: Peak = Peak::new();

/// Splice upstream pool: pooled TCP/TLS connection reused.
pub(crate) static POOL_REUSED: Counter = Counter::new();
/// Splice upstream pool: fresh TCP/TLS connection opened.
pub(crate) static POOL_NEW: Counter = Counter::new();

/// Pool miss: no entry existed for this host (raise `POOL_MAX_IDLE_PER_HOST`).
pub(crate) static POOL_MISS_EMPTY: Counter = Counter::new();
/// Pool miss: pooled entry was already closed (lower `POOL_IDLE_TIMEOUT`).
pub(crate) static POOL_MISS_DEAD: Counter = Counter::new();
/// Pool miss: pooled entry's request failed in flight.
pub(crate) static POOL_MISS_FAILED: Counter = Counter::new();

/// Pool returns where the per-host slot was full and the oldest entry was
/// evicted (raise `POOL_MAX_IDLE_PER_HOST` if recurring).
pub(crate) static POOL_RETURN_EVICTED: Counter = Counter::new();

/// Downloads rejected by `CacheQuota::try_acquire` (would exceed `disk_quota`).
pub(crate) static DOWNLOAD_REJECTED_QUOTA: Counter = Counter::new();

/// Permanent-file cache lookup found a usable file.
pub(crate) static CACHE_HITS: Counter = Counter::new();
/// Permanent-file cache lookup needed a fetch (volatile cases use VOLATILE_*).
pub(crate) static CACHE_MISSES: Counter = Counter::new();

/// Cached responses served via mmap (companion to `BYTES_SERVED_MMAP`).
pub(crate) static REQUESTS_MMAP: Counter = Counter::new();
/// Cached responses served via sendfile (companion to `BYTES_SERVED_SENDFILE`).
pub(crate) static REQUESTS_SENDFILE: Counter = Counter::new();
/// Responses served via splice (companion to `BYTES_SERVED_SPLICE`).
pub(crate) static REQUESTS_SPLICE: Counter = Counter::new();
/// Cached responses served via plain copy (companion to `BYTES_SERVED_COPY`).
pub(crate) static REQUESTS_COPY: Counter = Counter::new();
/// Late-joiner responses streamed via `ChannelBody` (companion to
/// `BYTES_SERVED_CHANNEL`).
pub(crate) static REQUESTS_CHANNEL: Counter = Counter::new();

/// Mirror responses that violated the HTTP contract: body exceeded or
/// undershot the announced `Content-Length`, missing or mismatched
/// `Content-Range`, missing `Content-Length` on a non-volatile fetch.
/// Any non-zero value points to a misbehaving upstream.
pub(crate) static UPSTREAM_PROTOCOL_VIOLATION: Counter = Counter::new();

/// Hyper-backend upstream request failures during connect / TLS / before any
/// response was received. Splice-path equivalents are
/// `UPSTREAM_CONNECT_FAILED` / `UPSTREAM_TLS_FAILED`.
pub(crate) static UPSTREAM_HYPER_CONNECT_FAILED: Counter = Counter::new();
/// Hyper-backend upstream errors observed *after* response headers were
/// received, while streaming the body (peer aborted / framing error).
pub(crate) static UPSTREAM_HYPER_BODY_ERR: Counter = Counter::new();

/// Local cache I/O failures: stat/open of cached files returning a 5xx to
/// the client. Distinct from `CACHE_SIZE_CORRUPTION`, which is specific to
/// on-disk size accounting drift.
pub(crate) static CACHE_IO_FAILURE: Counter = Counter::new();

/// Bytes copied client → upstream through the CONNECT tunnel.
pub(crate) static BYTES_TUNNELED_CLIENT_TO_UPSTREAM: Accumulator = Accumulator::new();
/// Bytes copied upstream → client through the CONNECT tunnel.
pub(crate) static BYTES_TUNNELED_UPSTREAM_TO_CLIENT: Accumulator = Accumulator::new();

/// HTTP timeout firings: upstream body read.
pub(crate) static HTTP_TIMEOUT_UPSTREAM_READ: Counter = Counter::new();
/// HTTP timeout firings: upstream TCP/TLS handshake.
pub(crate) static HTTP_TIMEOUT_UPSTREAM_CONNECT: Counter = Counter::new();
/// HTTP timeout firings: client failing to drain the response in time.
pub(crate) static HTTP_TIMEOUT_CLIENT: Counter = Counter::new();

/// `max_upstream_downloads` saturation episodes — debounced (latched at cap,
/// cleared when the active set drains to zero). Climbing → recurring saturation.
pub(crate) static UPSTREAM_DOWNLOAD_CAP_TRANSITIONS: Counter = Counter::new();

/// Requests rejected (503) because the active-download set was already at the cap.
pub(crate) static UPSTREAM_DOWNLOAD_REJECTED_CAP: Counter = Counter::new();

/// Retry attempts in `request_with_retry` past the first (connect failures).
pub(crate) static UPSTREAM_RETRIES: Counter = Counter::new();

/// Log-ring evictions due to overflow (raise `logstore_capacity` if non-zero).
pub(crate) static LOGSTORE_EVICTIONS: Counter = Counter::new();

/// Peak cache disk-quota utilization in basis points (10000 = 100%).
/// Only meaningful when `disk_quota` is configured; otherwise stays at 0.
pub(crate) static CACHE_QUOTA_UTIL_PEAK_BPS: Peak = Peak::new();

/// HTTPS upgrade attempted on an HTTP request (Auto / uncached scheme).
pub(crate) static HTTPS_UPGRADE_ATTEMPTED: Counter = Counter::new();
/// HTTPS upgrade succeeded (https scheme cached for the host).
pub(crate) static HTTPS_UPGRADE_SUCCEEDED: Counter = Counter::new();
/// HTTPS upgrade failed and was reverted to the original scheme.
pub(crate) static HTTPS_UPGRADE_FAILED: Counter = Counter::new();

/// Scheme-cache entries purged after `MAX_ATTEMPTS` connection failures.
pub(crate) static SCHEME_CACHE_REMOVED: Counter = Counter::new();

/// Database operations in `db_loop` that returned an error (any kind).
pub(crate) static DB_OPERATION_FAILED: Counter = Counter::new();

/// Active downloads that finished in `Aborted` state (rate-limit / failure).
pub(crate) static DOWNLOADS_ABORTED: Counter = Counter::new();

/// Cache-size reconciliation events with a non-zero on-disk delta.
pub(crate) static RECONCILE_EVENTS: Counter = Counter::new();
/// Total absolute bytes corrected by reconciliation events.
pub(crate) static RECONCILE_BYTES_REPAIRED: Accumulator = Accumulator::new();

/// `error!("Cache size corruption: …")` events — any non-zero is a bug signal.
pub(crate) static CACHE_SIZE_CORRUPTION: Counter = Counter::new();

/// Authorization rejection: client request denied by the mirror allowlist.
pub(crate) static AUTHZ_REJECTED_MIRROR: Counter = Counter::new();
/// Authorization rejection: client request denied by the client allowlist.
pub(crate) static AUTHZ_REJECTED_CLIENT: Counter = Counter::new();
/// Authorization rejection: HTTPS-tunnel CONNECT denied by the tunnel-mirror list.
pub(crate) static AUTHZ_REJECTED_TUNNEL_MIRROR: Counter = Counter::new();

/// kTLS receive offload was enabled on an upstream connection.
pub(crate) static KTLS_RX_ENABLED: Counter = Counter::new();
/// kTLS fell back to userspace TLS for the rest of the connection.
pub(crate) static KTLS_FALLBACK_PERMANENT: Counter = Counter::new();
/// kTLS fell back to userspace TLS for a single record (recovered after).
pub(crate) static KTLS_FALLBACK_TRANSIENT: Counter = Counter::new();

/// Transfers cancelled because the upstream min-rate threshold was not met.
pub(crate) static RATE_LIMIT_UPSTREAM: Counter = Counter::new();
/// Transfers cancelled because the client min-rate threshold was not met.
pub(crate) static RATE_LIMIT_CLIENT: Counter = Counter::new();

/// `DatabaseCommand` enqueues via `send_db_command` (every send is counted).
pub(crate) static DB_COMMANDS_SENT: Counter = Counter::new();
/// Peak observed DB-command channel depth, sampled post-send by the producer.
pub(crate) static DB_QUEUE_DEPTH_PEAK: Peak = Peak::new();
/// Sends that observed a fully-saturated channel and had to wait for a slot.
pub(crate) static DB_QUEUE_FULL_WAITS: Counter = Counter::new();
/// Debounced `DB_QUEUE_FULL_WAITS` — counts each saturation episode once
/// (latched until the channel drains fully to empty).
pub(crate) static DB_QUEUE_FULL_TRANSITIONS: Counter = Counter::new();

/// Total cache files evicted across all cleanup runs.
pub(crate) static CLEANUP_EVICTIONS: Accumulator = Accumulator::new();
/// Total bytes reclaimed across all cleanup runs.
pub(crate) static CLEANUP_BYTES_RECLAIMED: Accumulator = Accumulator::new();

/// Last cleanup run: duration in seconds (atomically updated; readers may
/// observe a transient mix across the trio between updates).
pub(crate) static LAST_CLEANUP_DURATION_SECS: StateU64 = StateU64::new();
/// Last cleanup run: number of files removed.
pub(crate) static LAST_CLEANUP_FILES_REMOVED: StateU64 = StateU64::new();
/// Last cleanup run: bytes reclaimed.
pub(crate) static LAST_CLEANUP_BYTES_RECLAIMED: StateU64 = StateU64::new();

/// Record a client response status code into the matching class counter plus the
/// fine-grained bucket for statuses we track individually.
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
        _ => {}
    }
}

/// Record an upstream response status code. Tracks status-class buckets and
/// the 304 fast-path independently from the client-side `record_status`.
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
        StatusCode::MOVED_PERMANENTLY => UPSTREAM_STATUS_301.increment(),
        StatusCode::FOUND => UPSTREAM_STATUS_302.increment(),
        StatusCode::NOT_MODIFIED => UPSTREAM_STATUS_304.increment(),
        _ => {}
    }
}
