//! Splice-based upstream proxy for the sendfile backend: connects to the
//! mirror (HTTP or HTTPS), moves the response body to the client socket via
//! tee+splice fan-out while caching it to disk, and commits the download
//! through `RenameBarrier`.
//!
//! This file owns the entry point the sendfile backend calls
//! ([`splice_proxy`]) and the types it matches on ([`SpliceProxyOutcome`],
//! [`SpliceProxyError`], [`UpstreamFailure`], [`AfterHeaderSide`]), the
//! request drive ([`splice_proxy_drive`] and its phase functions) and the
//! per-request state structs ([`ClientConn`],
//! [`CacheTarget`], [`RateTimestamps`]). The mechanics live in submodules:
//!
//! - [`upstream`]: the `UpstreamConn` enum, the idle pool and `PoolGuard`,
//!   TCP/TLS connect and connect-error classification.
//! - [`http`]: request formatting, response-head parsing into
//!   `UpstreamResponse`, the `BodyFraming` relays and the chunked decoder.
//! - [`acquire`]: standard connect with retry/backoff, redirect and
//!   partial-discard reconnects, each yielding an `UpstreamExchange`.
//! - [`body`]: the zero-copy and userspace-TLS body loops on `BodyTransfer`,
//!   client demotion to file serving, pipe helpers.
//! - [`detached`]: the client-less download the parallel-download hack's
//!   nudge leaves running after the 429 went out.
//! - [`volatile`]: the buffered download path for volatile responses without
//!   `Content-Length`.
//! - `cleanup_bridge` (hyper-less builds): cleanup's index fetch entry.
//! - [`simple_proxy`]: the cache-less pass-through relay.

mod acquire;
mod body;
#[cfg(not(feature = "hyper"))]
mod cleanup_bridge;
mod detached;
mod http;
mod simple_proxy;
mod upstream;
mod volatile;

#[cfg(not(feature = "hyper"))]
pub(crate) use cleanup_bridge::process_cache_request;
pub(crate) use simple_proxy::splice_simple_proxy;
#[cfg(feature = "tls_rustls")]
pub(crate) use upstream::TLS_CLIENT_CONFIG;

use std::{
    io::ErrorKind,
    num::NonZero,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use ::http::StatusCode;
use tokio::{io::AsyncWriteExt as _, net::TcpStream};
use tracing::{debug, error, info, trace};

use crate::cache_conditional::{RangeRequestHeaders, ServeParams};
use crate::cache_layout::{CachedFlavor, ConnectionDetails};
use crate::cache_paths::CachePaths;
use crate::cache_quota::QuotaExceeded;
use crate::database_task::{DatabaseCommand, DbCmdTransfer, TransferKind, send_db_command};
use crate::deb_mirror::Origin;
use crate::error::{ErrorReport, is_peer_disconnect};
use crate::fs_open::{
    CacheAccessFailure, regular_file_metadata, tokio_nofollow_options, touch_volatile_mtime,
};
use crate::guards::{DownloadBarrier, InitBarrier};
use crate::http_helpers::{
    ConnectionAction, ConnectionVersion, OptHeader, WritePhase, write_416_response,
    write_all_to_stream, write_invalid_response,
};
use crate::http_range::{HttpDate, ParsedRange, format_http_date, http_parse_range};
use crate::humanfmt::HumanFmt;
use crate::log_once::Logged;
use crate::parallel_hack::{NUDGE_BODY, log_nudge, nudge_head, should_nudge};
use crate::partial_file::{self, TempPath, tokio_tempfile};
use crate::precise_instant::PreciseInstant;
use crate::rate_checker::{RateCheckDirection, RateChecker};
use crate::rate_log;
use crate::response_head::WireBody;
use crate::sendfile_conn::{
    SendfileResult, async_sendfile, serve_file_via_sendfile, write_all_to_stream_rated,
};
use crate::tcp_cork_guard::CorkGuard;
use crate::upstream_head::{
    ContentLength, DownloadPlan, RejectReason, ResumeAnomaly, ResumeState, plan_download,
    plan_fresh_download,
};
use crate::{
    AppState,
    active_downloads::{ActiveDownloadStatus, OriginateOutcome},
    build_info::APP_VIA,
    cache_metadata::{self, write_upstream_metadata},
    content_type::{content_type_for_cached_file, warn_on_content_type_mismatch},
    global_cache_quota, global_config, global_verify_throttle, info_or_warn, metrics,
    static_assert, warn_once_or_debug, warn_once_or_info, warn_once_or_info_logged,
};

use acquire::{
    UpstreamExchange, discard_partial_and_retry, follow_redirect, standard_upstream_connect,
    warn_upstream_reject,
};
use body::{
    BodyOutcome, BodyTransfer, BodyTransferError, DeliveryResult, DemotedClientHandle,
    SpliceRangeFilter, range_slice, splice_proxy_body, splice_proxy_body_tls,
};
use detached::DetachedDownload;
use http::UpstreamResponse;
use simple_proxy::rewrite_simple_proxy_headers;
use upstream::{ConnLabel, PoolGuard, UnconsumedBodyGuard};
use volatile::handle_volatile_buffered_download;

// On Linux, EAGAIN and EWOULDBLOCK share the same numeric value, so matching
// one variant is equivalent to matching both. The nix crate models EWOULDBLOCK
// as a const alias of EAGAIN, which would make `EAGAIN | EWOULDBLOCK` an
// unreachable-pattern error. This assertion documents the equivalence once,
// so the individual `Err(Errno::EAGAIN)` arms throughout this module do not
// need to repeat it.
static_assert!(nix::errno::Errno::EAGAIN as i32 == nix::errno::Errno::EWOULDBLOCK as i32);

/// Conditional headers for volatile resource revalidation.
/// Sent to upstream when a cached volatile file is stale (>30s).
struct VolatileCondHeaders {
    if_modified_since: String,
    if_none_match: Option<Arc<str>>,
}

/// The client side of a splice exchange: the socket plus the protocol
/// version and keep-alive decision every response head is rendered with.
/// `Copy`, so the phase helpers take it by value instead of repeating the
/// stream/version/action triple in their signatures.
#[derive(Clone, Copy)]
struct ClientConn<'a> {
    stream: &'a TcpStream,
    version: ConnectionVersion,
    action: ConnectionAction,
}

impl ClientConn<'_> {
    /// Answer the request with a proxy-generated error response; `phase`
    /// tags a failed write.
    async fn write_invalid(
        self,
        status: StatusCode,
        msg: &'static str,
        retry_after: Option<Duration>,
        phase: &'static str,
    ) -> Result<(), SpliceProxyError> {
        write_invalid_response(
            self.stream,
            self.version,
            self.action,
            status,
            msg,
            retry_after,
        )
        .await
        .map_err(SpliceProxyError::client(phase))
    }
}

/// Maximum bytes to forward for volatile responses (no Content-Length / chunked non-cacheable).
const VOLATILE_BODY_MAX: usize = 1024 * 1024;

/// Splice-based proxy: connects to upstream (HTTP or HTTPS), transfers the response body
/// to the client socket via tee+splice fan-out while caching to disk.
///
/// For plain TCP upstreams, the entire path is zero-copy (splice from socket).
/// For TLS upstreams, the upstream read goes through userspace (decryption), but the
/// fan-out to client + cache still benefits from tee+splice.
pub(crate) async fn splice_proxy(
    client_stream: &TcpStream,
    conn_version: ConnectionVersion,
    conn_action: ConnectionAction,
    conn_details: &ConnectionDetails,
    upstream_path: &str,
    appstate: &AppState,
    client_range: RangeRequestHeaders<'_>,
) -> Result<SpliceProxyOutcome, SpliceProxyError> {
    // Register with active downloads to coordinate with concurrent clients.
    // A `Concurrent` outcome means another download for this key won the race
    // between sendfile's earlier `attach()` and our `originate()` here. It is
    // an alternate success — the caller retries as a sendfile late joiner
    // instead of falling all the way back to hyper. No late-joiner double
    // count, since `attach()` and `insert()` are mutually exclusive paths.
    let (init_tx, status) = match appstate.active_downloads.originate(conn_details.key()) {
        OriginateOutcome::Originator { init_tx, status } => (init_tx, status),
        OriginateOutcome::Concurrent { status } => {
            return Ok(SpliceProxyOutcome::Concurrent { status });
        }
        OriginateOutcome::AtCapacity { max } => {
            return Ok(SpliceProxyOutcome::AtCapacity { max });
        }
    };

    let client = ClientConn {
        stream: client_stream,
        version: conn_version,
        action: conn_action,
    };

    // TODO: use become: https://github.com/rust-lang/rust/issues/112788
    splice_proxy_drive(
        client,
        conn_details,
        upstream_path,
        appstate,
        client_range,
        init_tx,
        status,
    )
    .await
}

/// Serve a cached volatile file after an upstream `304 Not Modified`: refresh
/// the freshness window via `touch_volatile_mtime`, release the init barrier,
/// then deliver the file with `sendfile(2)`. The per-path bits (status
/// recording, upstream-connection pooling, `debug!` wording) stay at the
/// call site, and `invalid_tag` carries the call-site location tag for
/// `SpliceProxyError::Client`.
async fn serve_volatile_304_via_sendfile(
    client: ClientConn<'_>,
    conn_details: &ConnectionDetails,
    cache_path: &Path,
    client_range: RangeRequestHeaders<'_>,
    ibarrier: InitBarrier<'_>,
    invalid_tag: &'static str,
) -> Result<(), SpliceProxyError> {
    if !conn_details.client.is_cleanup_synthetic() {
        metrics::VOLATILE_REFETCHED_UPTODATE.increment();
    }

    let file = match tokio_nofollow_options().read(true).open(cache_path).await {
        Ok(f) => f,
        Err(err) => {
            return Err(SpliceProxyError::Cache(Logged::cache_io_failure(
                format_args!(
                    "splice proxy: failed to open cached file `{}` after 304; returning 500:  {}",
                    cache_path.display(),
                    ErrorReport(&err)
                ),
            )));
        }
    };
    let file = touch_volatile_mtime(file, cache_path).await;
    ibarrier.finished(cache_path.to_path_buf()).await;

    match serve_file_via_sendfile(
        client.stream,
        conn_details,
        "",
        (file, None, cache_path),
        (client.version, client.action),
        client_range,
        None,
    )
    .await
    {
        SendfileResult::Served(_)
        | SendfileResult::ClientError
        | SendfileResult::AfterHeaderError => Ok(()),
        SendfileResult::Invalid { status, msg } => {
            client.write_invalid(status, msg, None, invalid_tag).await
        }
    }
}

/// Resolve the client's `Range` against the object's `total` size, answering
/// the 416 on the client's behalf when it cannot be satisfied (`Ok(None)`;
/// `phase_416` tags a failed 416 write). `cache_time` and `etag` are what an
/// `If-Range` is compared against. A malformed `Range` is served in full, as
/// RFC 9110 allows, with a once-gated warn since a client expecting a resume
/// then gets everything.
async fn resolve_client_range(
    client: ClientConn<'_>,
    conn_details: &ConnectionDetails,
    client_range: RangeRequestHeaders<'_>,
    total: u64,
    cache_time: HttpDate,
    etag: Option<&str>,
    phase_416: &'static str,
) -> Result<Option<ServeParams>, SpliceProxyError> {
    let parsed = client_range.range.map(|range| {
        let parsed = http_parse_range(range, client_range.if_range, total, cache_time, etag);
        if matches!(parsed, ParsedRange::Invalid) {
            warn_once_or_debug!(
                "splice proxy: ignoring malformed Range header `{}` from client {}; serving the full file",
                range.escape_debug(),
                conn_details.client
            );
        }
        parsed
    });
    if let Ok(plan) = ServeParams::from_parsed(parsed, total) {
        return Ok(Some(plan));
    }
    write_416_response(client.stream, client.version, client.action, total)
        .await
        .map_err(SpliceProxyError::client(phase_416))?;
    Ok(None)
}

/// Render the `200 OK` / `206 Partial Content` head of a splice-served body:
/// the same bytes for the streaming drive and the buffered volatile path.
/// Deliberately not built on `ResponseHead::render`, which orders the
/// headers differently; the wire bytes are pinned by the
/// `splice_response_head_renders_the_pinned_bytes` test.
fn render_splice_response_head(
    conn_version: ConnectionVersion,
    conn_action: ConnectionAction,
    upstream_resp: &UpstreamResponse,
    range: &ServeParams,
    content_type: &str,
    date: &str,
) -> String {
    let status_line = range.status_line();
    let response_content_length = range.content_length;
    // `Age: 0` is a constant here: a fresh response streamed straight from
    // the origin has spent no time in a cache (RFC 9111 section 4.2.3).
    format!(
        "{conn_version} {status_line}\r\n\
         Date: {date}\r\n\
         Via: {APP_VIA}\r\n\
         Connection: {conn_action}\r\n\
         Content-Length: {response_content_length}\r\n\
         Content-Type: {content_type}\r\n\
         {last_modified_header}\
         {etag_header}\
         Accept-Ranges: bytes\r\n\
         Age: 0\r\n\
         {content_range_header}\
         \r\n",
        last_modified_header = OptHeader("Last-Modified", upstream_resp.last_modified.as_deref()),
        etag_header = OptHeader("ETag", upstream_resp.etag.as_deref()),
        content_range_header = OptHeader("Content-Range", range.content_range.as_deref()),
    )
}

/// Write the response head of a splice-served body to the client. The
/// caller has corked the socket, so the head coalesces with the body bytes
/// written right after. Records the client status and the per-response
/// `REQUESTS_SPLICE` bump, and returns the instant the first byte headed to
/// the client (start of the client-rate window). `phase` tags a failed
/// write.
async fn write_splice_response_headers(
    client: ClientConn<'_>,
    conn_details: &ConnectionDetails,
    upstream_resp: &UpstreamResponse,
    range: &ServeParams,
    phase: &'static str,
) -> Result<PreciseInstant, SpliceProxyError> {
    let content_type = content_type_for_cached_file(&conn_details.debname);
    warn_on_content_type_mismatch(
        upstream_resp.content_type.as_deref(),
        &conn_details.mirror,
        &conn_details.debname,
    );
    let date = format_http_date();
    let response_headers = render_splice_response_head(
        client.version,
        client.action,
        upstream_resp,
        range,
        content_type,
        &date,
    );

    trace!(
        "Outgoing {} response:\n{response_headers}",
        range.status_line()
    );

    metrics::record_client_status(range.http_status());
    // Bump once per splice-served response, regardless of whether the body
    // ends up flowing through `splice_proxy_body{,_tls}`, the body-prefix
    // direct write, or the buffered volatile write.
    metrics::REQUESTS_SPLICE.increment();
    // Start of the client-rate window: the first byte heading to the client.
    let t_client_first = PreciseInstant::now();
    write_all_to_stream(
        client.stream,
        response_headers.as_bytes(),
        WritePhase::Header,
    )
    .await
    .map_err(SpliceProxyError::client(phase))?;
    Ok(t_client_first)
}

/// Everything a download writes into: the open temp/partial file with its
/// path guard, the final cache path, and the barrier the download reports
/// progress on. Built by [`prepare_cache_target`], consumed by
/// [`commit_and_record`].
struct CacheTarget {
    tempfile: tokio::fs::File,
    temppath: TempPath,
    dest_path: PathBuf,
    dbarrier: DownloadBarrier,
}

/// Reserve the cache quota and open the file the body is written into: the
/// cache directory, the previous volatile copy's size (freed by the
/// overwrite), the quota reservation, the temp/partial file per `partial`,
/// the validator and expected-size xattrs, and the `InitBarrier ->
/// DownloadBarrier` transition. Shared by the streaming drive and the
/// buffered volatile path (which always passes `PartialDownload::Volatile`).
///
/// `Ok(None)` means a rejection was already written to the client: the
/// `503 Disk quota reached` (tagged `quota_phase`) or the 500 for a
/// `Resumable` partial that does not hold exactly `resume_offset` bytes.
#[expect(
    clippy::too_many_arguments,
    reason = "one call per download path; the arguments are the download's identity"
)]
async fn prepare_cache_target(
    client: ClientConn<'_>,
    conn_details: &ConnectionDetails,
    upstream_resp: &UpstreamResponse,
    partial: partial_file::PartialDownload,
    resume_offset: u64,
    total_content_length: NonZero<u64>,
    ibarrier: InitBarrier<'_>,
    quota_phase: &'static str,
) -> Result<Option<CacheTarget>, SpliceProxyError> {
    // Not created here: `integrity::rename_into_cache` creates it at commit
    // time, and only on `ENOENT`. Everything below tolerates its absence --
    // the volatile `prev_path` stat treats `NotFound` as "nothing to free",
    // and `dest_path` is pure path construction.
    let dest_dir = conn_details.cache_dir_path();

    let filename = Path::new(&conn_details.debname);
    assert!(
        filename.is_relative(),
        "path construction must not contain absolute components"
    );

    let prev_file_size = match conn_details.cached_flavor() {
        CachedFlavor::Volatile => {
            let prev_path = dest_dir.join(filename);
            match tokio::fs::symlink_metadata(&prev_path).await {
                Ok(m) if m.file_type().is_file() => m.len(),
                Ok(_) => {
                    metrics::CACHE_NON_REGULAR.increment();
                    error!(
                        "splice proxy: previous cache file `{}` is not a regular file; counting it as 0 bytes for the quota and overwriting it",
                        prev_path.display()
                    );
                    // `task_cache_scan` skips non-regular entries entirely
                    // (symlinks/FIFOs/sockets/dirs are not tallied into the
                    // tracked cache size), so the quota never accounted for
                    // them — there's nothing to "free" on overwrite.  0 is
                    // correct here and does not produce a reconciliation
                    // discrepancy.
                    0
                }
                Err(err) if err.kind() == ErrorKind::NotFound => 0,
                Err(err) => {
                    return Err(SpliceProxyError::Cache(Logged::cache_io_failure(
                        format_args!(
                            "splice proxy: failed to stat existing volatile file `{}`; returning 500:  {}",
                            prev_path.display(),
                            ErrorReport(&err)
                        ),
                    )));
                }
            }
        }
        CachedFlavor::Permanent => {
            // permanent files are never overwritten
            0
        }
    };

    let reservation = if conn_details.client.is_cleanup_synthetic() {
        // Mirrors the hyper gate: cleanup's own index fetches are admitted
        // over quota (`CacheQuota::acquire_for_cleanup`).
        global_cache_quota().acquire_for_cleanup(
            ContentLength::Exact(total_content_length),
            prev_file_size,
            &conn_details.debname,
        )
    } else {
        match global_cache_quota().try_acquire(
            ContentLength::Exact(total_content_length),
            prev_file_size,
            &conn_details.debname,
        ) {
            Ok(r) => r,
            Err(_err @ QuotaExceeded) => {
                client
                    .write_invalid(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "Disk quota reached",
                        None,
                        quota_phase,
                    )
                    .await?;
                return Ok(None);
            }
        }
    };

    // Create/open the output file: the partial path for permanent files, a
    // random temp file for volatile ones. The permanent arms take over the
    // caller's path guard, whose `OnDrop::Keep` is what leaves a failed
    // download's partial on disk for a later resume; the volatile temp file is
    // removed on drop instead.
    let (tempfile, temppath) = match partial {
        partial_file::PartialDownload::Resumable { mut file, guard } => {
            // Defense in depth: the held-open fd makes this size re-check
            // redundant, but a wrong offset here would corrupt the cache file.
            use tokio::io::AsyncSeekExt as _;
            let current_size = match file.seek(std::io::SeekFrom::End(0)).await {
                Ok(size) => size,
                Err(err) => {
                    // Substituting 0 makes the mismatch branch below report an
                    // empty partial file, which is not what happened -- the
                    // discarded errno is the whole diagnosis.
                    error!(
                        "splice proxy: failed to determine partial file size for {} from mirror {}; treating the partial as empty and returning 500:  {}",
                        conn_details.debname,
                        conn_details.mirror,
                        ErrorReport(&err)
                    );
                    0
                }
            };
            if current_size != resume_offset {
                error!(
                    "splice proxy: partial file size {current_size} != expected {resume_offset} for {} from mirror {} despite held fd; aborting the resume and returning 500",
                    conn_details.debname, conn_details.mirror
                );
                client
                    .write_invalid(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "Cache Access Failure",
                        None,
                        "partial-size mismatch 500",
                    )
                    .await?;
                return Ok(None);
            }
            (file, guard)
        }
        partial_file::PartialDownload::Fresh(guard) => partial_file::create_partial_file(
            guard, 0o640,
        )
        .await
        .map_err(|(err, path)| {
            SpliceProxyError::Cache(Logged::cache_io_failure(format_args!(
                "splice proxy: failed to create partial file `{}`; aborting the download:  {}",
                path.display(),
                ErrorReport(&err)
            )))
        })?,
        partial_file::PartialDownload::Volatile => {
            let tmppath = CachePaths::global().scratch_file(filename);
            tokio_tempfile(&tmppath, 0o640).await.map_err(|err| {
                SpliceProxyError::Cache(Logged::cache_io_failure(format_args!(
                    "splice proxy: failed to create temp file `{}`; aborting the download:  {}",
                    tmppath.display(),
                    ErrorReport(&err)
                )))
            })?
        }
    };

    let download_meta = cache_metadata::UpstreamMetadata::from_upstream(
        upstream_resp.etag.clone(),
        upstream_resp.last_modified.clone(),
    );
    // Persist the validators and the expected total early, so they survive
    // an interrupted download for resume.
    write_upstream_metadata(
        &tempfile,
        &temppath,
        &download_meta,
        Some(total_content_length.get()),
    );
    let dbarrier = ibarrier
        .download(
            temppath.to_path_buf(),
            ContentLength::Exact(total_content_length),
            reservation,
            Arc::new(download_meta),
        )
        .await;

    Ok(Some(CacheTarget {
        tempfile,
        temppath,
        dest_path: dest_dir.join(filename),
        dbarrier,
    }))
}

/// Sync and commit the fully written download into the cache, then record
/// the `Download` transfer and the `Origin` row. Returns `Some(elapsed)` --
/// the download duration from `start` to the commit, which the `Delivery`
/// record shares -- when the file landed in the cache. `None` means
/// `commit` failed: it logged the cause and dropped the barrier, the
/// temp-file guard removed the partial, and nothing is cached (future
/// requests re-download), so no DB row is written.
///
/// The `Origin` row uses `original_uri_path`, the pre-redirect client
/// request path, so the recorded origin layout is stable across upstream
/// redirects (the redirected `upstream_path` would otherwise poison the DB
/// with a different origin row for the same logical download).
async fn commit_and_record(
    target: CacheTarget,
    conn_details: &ConnectionDetails,
    original_uri_path: &str,
    total_content_length: NonZero<u64>,
    start: PreciseInstant,
) -> Option<Duration> {
    let CacheTarget {
        tempfile,
        temppath,
        dest_path,
        dbarrier,
    } = target;

    // Sync cache file to ensure durability
    if let Err(err) = tempfile.sync_all().await {
        metrics::CACHE_IO_FAILURE.increment();
        error!(
            "splice proxy: failed to sync cache file `{}`; committing it to the cache anyway:  {}",
            temppath.display(),
            ErrorReport(&err)
        );
    }
    drop(tempfile);

    // Move temp file to final cache path.
    // Lock to block all downloading tasks, since the file from the
    // path of the downloading state is going to be moved.
    let rbarrier = dbarrier.begin_rename().await;

    let cache_committed = rbarrier
        .commit(temppath, dest_path, total_content_length.get())
        .await
        .is_ok();

    let elapsed = start.elapsed();

    if !cache_committed {
        return None;
    }

    // Record download in database (mirrors download_file() in hyper_conn.rs).
    let cmd = DatabaseCommand::Transfer(DbCmdTransfer {
        mirror: conn_details.mirror.clone(),
        debname: conn_details.debname.clone(),
        size: total_content_length.get(),
        elapsed,
        client_ip: conn_details.client.ip(),
        kind: TransferKind::Download,
    });
    send_db_command(cmd).await;

    // Record origin in database for this cached download.  This is an
    // intentional asymmetry with the hyper backend: `Origin::from_path` is
    // only called from the hyper simple-proxy passthrough in
    // `hyper_conn.rs`; the hyper cache-download paths in
    // `download_file`/`serve_new_file` never record an Origin row.  The
    // splice path records Origins for cached downloads too, so it is doing
    // strictly more origin-recording work than hyper.  Treat the splice
    // origin write as the source of truth for cached-download origins for
    // now.
    if let Some(origin) = Origin::from_path(
        original_uri_path,
        conn_details.mirror.host().clone(),
        conn_details.mirror.port(),
    ) {
        let cmd = DatabaseCommand::Origin(origin);
        send_db_command(cmd).await;
    }

    Some(elapsed)
}

/// Per-request rate-logging timestamps for the completion line
/// ([`log_splice_completion`]).
struct RateTimestamps {
    /// Start of the upstream-rate window: the instant the upstream request
    /// was sent (falls back to a local instant only for bare-parser
    /// responses, i.e. tests).
    t_req_sent: PreciseInstant,
    /// End of the upstream-rate window. Initialised at construction so the
    /// case where the splice loop never runs (whole body arrived with the
    /// headers) still has a sane figure; reassigned right after the splice
    /// body block when it does run.
    t_upstream_done: PreciseInstant,
    /// Start of the client-rate window: just before the response-header
    /// write.
    t_client_first: PreciseInstant,
    /// End of the client-rate window: first set after the prefix writes,
    /// then reassigned after the splice body block and after the demoted
    /// file-serve task completes.
    t_client_done: PreciseInstant,
    /// Best-effort count of body bytes written toward the client, for the
    /// disconnect segment.
    client_bytes_sent: u64,
}

impl RateTimestamps {
    /// Open the upstream-rate window at `t_req_sent` and close it now; the
    /// client-window instants start as this same instant and are reassigned
    /// as that window opens and closes.
    fn new(t_req_sent: PreciseInstant) -> Self {
        let t_upstream_done = PreciseInstant::now();
        Self {
            t_req_sent,
            t_upstream_done,
            t_client_first: t_upstream_done,
            t_client_done: t_upstream_done,
            client_bytes_sent: 0,
        }
    }

    fn upstream_window(&self) -> Duration {
        self.t_upstream_done.duration_since(self.t_req_sent)
    }

    fn client_window(&self) -> Duration {
        self.t_client_done.duration_since(self.t_client_first)
    }
}

/// What became of the client a completed download was fetched for; selects
/// the event wording and the client rate segment of
/// [`log_splice_completion`].
#[derive(Clone, Copy)]
enum CompletionClient {
    /// The client received the whole response body; `bytes` is what its
    /// response promised.
    Served { bytes: u64 },
    /// The client was lost mid-body -- disconnect, stall, or a failed
    /// demoted file-serve -- and that failure was logged at its source.
    Lost,
    /// No client was ever attached: the parallel-hack nudge answered the
    /// request and the download ran detached ([`detached`]). Reports the
    /// upstream side only, in hyper's "Finished download of ..." wording
    /// plus the splice mechanism token -- there is no fused serve to name.
    Nudged,
}

/// The completion line of a download that landed in the cache: "Served and
/// cached ..." when the client got the whole response, "Cached ..." when the
/// client was lost mid-body, "Finished download of ..." when there was no
/// client. `upstream_bytes` is the wire body (the remainder on a resume).
fn log_splice_completion(
    conn_details: &ConnectionDetails,
    conn_label: ConnLabel,
    rates: &RateTimestamps,
    upstream_bytes: u64,
    resume_offset: u64,
    client: CompletionClient,
) {
    let in_time = conn_details.request_received_at.elapsed();
    let volatile = if conn_details.cached_flavor() == CachedFlavor::Volatile {
        "volatile "
    } else {
        ""
    };
    let upstream = rate_log::upstream_segment(upstream_bytes, rates.upstream_window());
    let (event, segments) = match client {
        CompletionClient::Served { bytes } => (
            "Served and cached",
            format!(
                "{upstream}, {}",
                rate_log::client_segment(bytes, rates.client_window())
            ),
        ),
        CompletionClient::Lost => (
            "Cached",
            format!(
                "{upstream}, {}",
                rate_log::client_disconnect_segment(rates.client_bytes_sent, rates.client_window())
            ),
        ),
        CompletionClient::Nudged => ("Finished download of", upstream),
    };
    info!(
        "{event} {volatile}file {} from mirror {} for client {} in {} via splice{conn_label} ({segments}){}",
        conn_details.debname,
        conn_details.mirror,
        conn_details.client,
        HumanFmt::Time(in_time),
        if resume_offset > 0 {
            format!(", resumed from {}", HumanFmt::Size(resume_offset))
        } else {
            String::new()
        },
    );
}

/// Record the `Delivery` transfer of a cached download the client received
/// in full; `elapsed` is the download duration from [`commit_and_record`].
async fn record_delivery(
    conn_details: &ConnectionDetails,
    total_content_length: NonZero<u64>,
    elapsed: Duration,
    partial: bool,
) {
    let cmd = DatabaseCommand::Transfer(DbCmdTransfer {
        mirror: conn_details.mirror.clone(),
        debname: conn_details.debname.clone(),
        size: total_content_length.get(),
        elapsed,
        kind: TransferKind::Delivery { partial },
        client_ip: conn_details.client.ip(),
    });
    send_db_command(cmd).await;
}

/// The pre-upstream verify-throttle gate: answers `503 Recently failed
/// checksum verification` (`Ok(true)`) while the file's recent checksum
/// failures keep it throttled. Cleanup probes bypass the throttle: they run
/// once per 24h cycle and a 503 would hard-fail the index-fetch cascade;
/// their commit outcome still records/clears throttle state. (Only the
/// hyper gate is reachable by cleanup today; kept here for parallel-path
/// symmetry.)
async fn reject_if_verify_throttled(
    client: ClientConn<'_>,
    conn_details: &ConnectionDetails,
) -> Result<bool, SpliceProxyError> {
    if conn_details.client.is_cleanup_synthetic() {
        return Ok(false);
    }
    let Some(throttled) = global_verify_throttle().check(conn_details.key()) else {
        return Ok(false);
    };
    warn_once_or_info!(
        "splice proxy: rejecting request for {} from client {}: recently failed checksum verification ({} consecutive failures), retry in {}",
        conn_details.debname,
        conn_details.client,
        throttled.failures,
        HumanFmt::Time(throttled.remaining)
    );
    metrics::DOWNLOAD_REJECTED_VERIFY_THROTTLE.increment();
    client
        .write_invalid(
            StatusCode::SERVICE_UNAVAILABLE,
            "Recently failed checksum verification",
            Some(throttled.remaining),
            "verify-throttle 503",
        )
        .await?;
    Ok(true)
}

/// Check for a partial download file to resume (permanent files only).
///
/// See [`partial_file::PartialDownload`] for the open-once and keep-on-drop
/// rules both backends resume under.
async fn open_partial_resume(
    ibarrier: &InitBarrier<'_>,
    conn_details: &ConnectionDetails,
) -> Result<partial_file::PartialResume, SpliceProxyError> {
    if conn_details.cached_flavor() != CachedFlavor::Permanent {
        return Ok(partial_file::PartialResume::volatile());
    }
    match partial_file::prepare_partial_resume(
        ibarrier,
        &conn_details.debname,
        &conn_details.mirror,
        "splice proxy: ",
    )
    .await
    {
        Ok(resume) => Ok(resume),
        Err(partial_file::PartialOpenFailure { logged, guard }) => {
            // Error already logged in `open_partial_file()`.
            drop(guard);
            Err(SpliceProxyError::Cache(logged))
        }
    }
}

/// Volatile revalidation: read the cached file's metadata for the
/// conditional headers. When a stale volatile file exists in cache, prepare
/// If-Modified-Since / If-None-Match headers so the upstream can respond
/// with 304 Not Modified if the content hasn't changed. Returns the headers
/// and the cached file's path; `None` for a permanent file and for a
/// volatile file that is not in the cache yet.
async fn read_volatile_validators(
    conn_details: &ConnectionDetails,
) -> Result<Option<(VolatileCondHeaders, PathBuf)>, SpliceProxyError> {
    if conn_details.cached_flavor() != CachedFlavor::Volatile {
        return Ok(None);
    }
    let cache_path = conn_details.cache_file_path();

    let file = match tokio_nofollow_options().read(true).open(&cache_path).await {
        Ok(f) => f,
        Err(err) if err.kind() == ErrorKind::NotFound => return Ok(None),
        Err(err) => {
            return Err(SpliceProxyError::Cache(Logged::cache_io_failure(
                format_args!(
                    "Failed to open volatile cached file `{}`; returning 500:  {}",
                    cache_path.display(),
                    ErrorReport(&err)
                ),
            )));
        }
    };
    let mdata = match regular_file_metadata(&file, &cache_path) {
        Ok(m) => m,
        Err(CacheAccessFailure(logged)) => {
            return Err(SpliceProxyError::Cache(logged));
        }
    };

    // Use mtime (last revalidated time), matching the hyper backend.
    // Mtime is repurposed as "last revalidated" by touch_volatile_mtime(),
    // so it correctly tells upstream "has this changed since I last checked?".
    let mtime = mdata
        .modified()
        .expect("Platform should support modification timestamps via setup check");
    let if_modified_since = HttpDate::from(mtime).format();
    let key = conn_details.key();
    let if_none_match = cache_metadata::store()
        .resolve(&key, &file, &cache_path)
        .etag
        .clone();
    Ok(Some((
        VolatileCondHeaders {
            if_modified_since,
            if_none_match,
        },
        cache_path,
    )))
}

/// Settle the upstream response into a [`DownloadPlan`]. Follows one 3xx
/// redirect (301/302/307/308) if the target host is allowed -- no loops,
/// matching hyper -- and does so first, before the resume/304/passthrough
/// handling, so those all operate on the (possibly redirected) response,
/// mirroring `hyper_conn.rs` which follows the redirect before its
/// `NOT_MODIFIED` check. Then discards malformed validators, counts a fresh
/// volatile body, and classifies the head; a resume anomaly discards the
/// partial (re-fetching without `Range` when the response is unusable) and
/// re-plans the fresh head. No reconnect helper runs past this point, so
/// the exchange is final on return.
async fn plan_upstream_response(
    exchange: &mut UpstreamExchange,
    conn_details: &ConnectionDetails,
    host_authority: &str,
    upstream_path: &str,
    resume: &mut partial_file::PartialResume,
    volatile_cond: Option<&VolatileCondHeaders>,
    volatile_cache_path: Option<PathBuf>,
) -> Result<DownloadPlan<PathBuf>, SpliceProxyError> {
    let redirect = if exchange.response.is_redirect() {
        follow_redirect(
            exchange,
            conn_details,
            upstream_path,
            resume.offset,
            resume.if_range.as_deref(),
            volatile_cond,
        )
        .await?
    } else {
        None
    };
    exchange.response.discard_invalid_validators(conn_details);

    // Volatile stale-but-present revalidation that returned a fresh body
    // (200 or 206): counterpart to the 304 / UPTODATE case in
    // `serve_volatile_304_via_sendfile`. The volatile-not-found path leaves
    // `volatile_cache_path` as None and is intentionally not split into
    // UPTODATE/OUTOFDATE.
    if volatile_cache_path.is_some()
        && (exchange.response.status_code == 200 || exchange.response.status_code == 206)
        && !conn_details.client.is_cleanup_synthetic()
    {
        metrics::VOLATILE_REFETCHED_OUTOFDATE.increment();
    }

    match plan_download(
        &exchange.response.head(),
        ResumeState::new(resume.offset, resume.expected_total),
        conn_details.cached_flavor(),
        volatile_cache_path,
        global_config().max_object_size,
    ) {
        Ok(plan) => Ok(plan),
        Err(anomaly) => {
            match anomaly {
                ResumeAnomaly::RangeIgnored => info!(
                    "splice proxy: server returned 200 instead of 206 for resume of {} from mirror {}, starting fresh",
                    conn_details.debname, conn_details.mirror
                ),
                ResumeAnomaly::RangeNotSatisfiable => warn_once_or_info!(
                    "splice proxy: server returned 416 for resume of {} from mirror {} (partial {}); discarding the stale partial and retrying fresh",
                    conn_details.debname,
                    conn_details.mirror,
                    HumanFmt::Size(resume.offset)
                ),
                ResumeAnomaly::ContentRangeMismatch => warn_once_or_info!(
                    "splice proxy: invalid or mismatched Content-Range in 206 for {} from mirror {}; discarding the partial and retrying fresh",
                    conn_details.debname,
                    conn_details.mirror
                ),
            }
            if anomaly.needs_refetch() {
                // After a redirect the discard-and-retry talks to the
                // redirect target, not to the original mirror with the
                // redirected path.
                let dial_mirror = conn_details.upstream_mirror();
                let (upstream_mirror, host_authority, upstream_path) = redirect.as_ref().map_or(
                    (&dial_mirror, host_authority, upstream_path),
                    |target| {
                        (
                            &target.mirror,
                            target.authority.as_str(),
                            target.path.as_str(),
                        )
                    },
                );
                discard_partial_and_retry(
                    &mut resume.partial,
                    upstream_mirror,
                    host_authority,
                    upstream_path,
                    exchange,
                    conn_details,
                )
                .await?;
            } else {
                resume.partial.discard_resume().await;
            }
            // A resume never revalidates: there is no cached copy to serve.
            Ok(plan_fresh_download(
                &exchange.response.head(),
                conn_details.cached_flavor(),
                None,
                global_config().max_object_size,
            ))
        }
    }
}

/// Forward a non-200/non-206 response directly to the client instead of
/// falling back to hyper (which would open a redundant second connection).
/// Nothing is cached, so the caller's `InitBarrier` fires on its return;
/// `PoolGuard::drop` returns the connection to the pool if still poolable.
async fn relay_passthrough(
    upstream: &mut PoolGuard,
    client: ClientConn<'_>,
    conn_details: &ConnectionDetails,
    upstream_resp: &UpstreamResponse,
    header_buf: &[u8],
    header_end: usize,
) -> Result<(), SpliceProxyError> {
    debug!(
        "splice proxy: upstream returned {}, forwarding directly",
        upstream_resp.status_code
    );

    let body_prefix = &header_buf[header_end..];
    if let Err(reason) = upstream_resp.check_relayable(body_prefix.len() as u64) {
        return reject_upstream_response(upstream, client, conn_details, reason).await;
    }

    metrics::REQUESTS_PASSTHROUGH.increment();
    metrics::record_client_status(upstream_resp.status_code);

    // Rewrite the response headers before forwarding: strip hop-by-hop
    // headers, emit a single `Connection:` matching our keep-alive
    // decision, drop `Content-Length` when chunked, and append `Via:`.
    // Nothing has been written to the client yet, so a malformed-header
    // error can safely bail to a 502 via the outer arm.
    let passthrough_headers = match rewrite_simple_proxy_headers(
        &header_buf[..header_end],
        client.version,
        client.action,
        upstream_resp.status_code,
    ) {
        Ok(s) => s,
        Err(err) => {
            let logged = warn_once_or_info_logged!(
                "splice proxy: failed to rewrite passthrough headers for {} from mirror {}; returning 502:  {}",
                conn_details.debname,
                conn_details.mirror,
                ErrorReport(&err)
            );
            upstream.unset_poolable();
            return Err(SpliceProxyError::Upstream(UpstreamFailure { err, logged }));
        }
    };
    write_all_to_stream(
        client.stream,
        passthrough_headers.as_bytes(),
        WritePhase::Header,
    )
    .await
    .map_err(SpliceProxyError::client("passthrough headers"))?;

    // Forward the body that arrived with the headers plus the rest,
    // framed per the upstream's (precedence-resolved) framing.
    upstream_resp
        .framing
        .relay_to_client(upstream, client.stream, body_prefix, VOLATILE_BODY_MAX)
        .await
        .map_err(SpliceProxyError::after_header_client("passthrough body"))?;

    metrics::SERVED_PASSTHROUGH.increment();
    metrics::SERVED_TOTAL.increment();
    Ok(())
}

/// Answer a protocol-violating or unusable upstream response with a 502.
/// Body bytes in the `header_buf` tail or on the socket cannot be safely
/// skipped, so the connection does not return to the pool.
async fn reject_upstream_response(
    upstream: &mut PoolGuard,
    client: ClientConn<'_>,
    conn_details: &ConnectionDetails,
    reason: RejectReason,
) -> Result<(), SpliceProxyError> {
    reason.record_metrics();
    warn_upstream_reject(reason, conn_details);
    upstream.unset_poolable();
    client
        .write_invalid(
            StatusCode::BAD_GATEWAY,
            reason.body(),
            None,
            "upstream reject 502",
        )
        .await
}

/// The bytes the splice loop has to move once the body prefix that arrived
/// with the headers is subtracted from the declared body length. `Ok(None)`
/// means the prefix exceeds that length -- the same condition
/// [`UpstreamResponse::check_relayable`] refuses on the relay paths, so it
/// takes the same [`RejectReason::InconsistentBodyFraming`] 502 rather than
/// a wording and a body of its own.
async fn splice_body_count(
    upstream: &mut PoolGuard,
    client: ClientConn<'_>,
    conn_details: &ConnectionDetails,
    body_content_length: NonZero<u64>,
    body_prefix: &[u8],
) -> Result<Option<u64>, SpliceProxyError> {
    let prefix_len = body_prefix.len() as u64;
    if let Some(splice_count) = body_content_length.get().checked_sub(prefix_len) {
        return Ok(Some(splice_count));
    }
    reject_upstream_response(
        upstream,
        client,
        conn_details,
        RejectReason::InconsistentBodyFraming {
            content_length: body_content_length.get(),
            prefix_len,
        },
    )
    .await?;
    Ok(None)
}

/// The debug line opening a download. A served download reads "downloading
/// and serving ... for client ..."; a nudged one (`detached`) never had a
/// client attached and reads "downloading ... after nudging client ...",
/// since that client already moved on to its retry.
fn log_download_start(
    conn_details: &ConnectionDetails,
    conn_label: ConnLabel,
    resume_offset: u64,
    total_content_length: NonZero<u64>,
    nudged: bool,
) {
    let (serving, client) = if nudged {
        ("", " after nudging client")
    } else {
        (" and serving", " for client")
    };
    if resume_offset > 0 {
        #[expect(clippy::cast_precision_loss, reason = "only for display purpose")]
        let resume_percent = resume_offset as f32 / total_content_length.get() as f32 * 100.0;

        debug!(
            "splice proxy{conn_label}: resuming{serving} {} from mirror {}{client} {} at byte {} ({:.1}%)...",
            conn_details.debname,
            conn_details.mirror,
            conn_details.client,
            resume_offset,
            resume_percent
        );
    } else {
        debug!(
            "splice proxy{conn_label}: downloading{serving} {} from mirror {}{client} {}...",
            conn_details.debname, conn_details.mirror, conn_details.client
        );
    }
}

/// For resumed downloads, send the existing partial file content to the
/// client first using sendfile(2) for zero-copy transfer from the cache file
/// to the client socket. With a client Range, only send the overlap of
/// `[0, resume_offset)` with the range. Returns the bytes sent.
async fn send_resumed_prefix(
    client_stream: &TcpStream,
    temppath: &TempPath,
    range_plan: &ServeParams,
    resume_offset: u64,
) -> Result<u64, SpliceProxyError> {
    if resume_offset == 0 {
        return Ok(0);
    }
    let send_start = range_plan.content_start.min(resume_offset);
    let send_end = range_plan.content_end().min(resume_offset);
    if send_end <= send_start {
        return Ok(0);
    }
    let partial_reader = tokio_nofollow_options()
        .read(true)
        .open(temppath.as_ref())
        .await
        .map_err(|err| SpliceProxyError::AfterHeader {
            phase: "resume reopen",
            side: AfterHeaderSide::Cache(Logged::cache_io_failure(format_args!(
                "splice proxy: failed to reopen partial file `{}` for resume; aborting the transfer and closing the connection:  {}",
                temppath.display(),
                ErrorReport(&err)
            ))),
        })?;

    match async_sendfile(
        client_stream,
        &partial_reader,
        send_start,
        send_end - send_start,
    )
    .await
    {
        Ok(sent) => Ok(sent),
        Err((_sent, err)) => Err(SpliceProxyError::AfterHeader {
            phase: "resume sendfile to client",
            side: AfterHeaderSide::Client(err),
        }),
    }
}

/// Write the body bytes upstream sent in the same read as the headers to the
/// cache file and notify the late joiners. The cache half of
/// [`write_body_prefix`], split out so the client-less detached download
/// ([`detached::DetachedDownload`]) shares exactly these bytes and this one
/// error line.
///
/// `consequence` is the log line's consequence clause: the two callers end
/// differently, since the detached download has no connection to close (see
/// `body::BodyTransferError::log_detached`, which draws the same
/// distinction).
async fn write_body_prefix_to_cache(
    target: &mut CacheTarget,
    body_prefix: &[u8],
    consequence: &'static str,
) -> Result<(), SpliceProxyError> {
    if body_prefix.is_empty() {
        return Ok(());
    }

    // The bytes are already in our hands, so the cache file is the source of
    // truth that other clients read from; the caller only attempts its
    // client write after this returned. Flushing before the splice loop also
    // keeps the queued write from racing the loop's raw `splice(2)` appends
    // to the same fd.
    write_all_flushed(&mut target.tempfile, body_prefix)
        .await
        .map_err(|err| SpliceProxyError::AfterHeader {
            phase: "body prefix to cache",
            side: AfterHeaderSide::Cache(Logged::cache_io_failure(format_args!(
                "splice proxy: failed to write body prefix to cache file `{}`; {consequence}:  {}",
                target.temppath.display(),
                ErrorReport(&err)
            ))),
        })?;

    // Notify concurrent clients of progress.
    target.dbarrier.ping();

    Ok(())
}

/// Write `bytes` to a cache temp file and wait for them to land.
///
/// `tokio::fs::File::write_all` only queues the write on the blocking pool;
/// the follow-up `flush` waits for it, so a failure (e.g. disk full)
/// surfaces at the caller's classified site. Without it the error stays
/// parked in the file handle -- `sync_all` at commit time never reports a
/// deferred write error -- and a truncated file would be renamed in as a
/// success.
async fn write_all_flushed(file: &mut tokio::fs::File, bytes: &[u8]) -> std::io::Result<()> {
    file.write_all(bytes).await?;
    file.flush().await
}

/// Cache the body prefix ([`write_body_prefix_to_cache`]), then write the
/// range-filtered part of it to the client. When the whole body arrived in
/// the head read, the prefix holds the full file.
///
/// Returns whether the client write failed. That error is swallowed to keep
/// caching the buffered prefix, but if the splice loop never runs (entire
/// body is in the prefix; `splice_count == 0`) the caller must close the
/// connection at the end so the handler does not keep-alive a socket whose
/// write side just broke and does not claim success after sending fewer
/// bytes than `Content-Length`.
async fn write_body_prefix(
    client_stream: &TcpStream,
    conn_details: &ConnectionDetails,
    target: &mut CacheTarget,
    body_prefix: &[u8],
    range_plan: &ServeParams,
    resume_offset: u64,
    rates: &mut RateTimestamps,
) -> Result<bool, SpliceProxyError> {
    write_body_prefix_to_cache(
        target,
        body_prefix,
        "aborting the download and closing the connection",
    )
    .await?;
    if body_prefix.is_empty() {
        return Ok(false);
    }

    // If the client has disconnected, we log and keep filling the cache; if
    // the splice loop later observes the broken client connection, it will
    // continue via its disconnect/cache-only handling instead of dropping
    // these prefix bytes from the cache entirely.
    let mut prefix_client_failed = false;
    // The prefix starts at the resume offset: it is the first body byte the
    // upstream sent, and everything before it is already in the partial file.
    let client_slice = range_slice(
        body_prefix,
        resume_offset,
        range_plan.content_start,
        range_plan.content_length,
    );
    if !client_slice.is_empty() {
        let config = global_config();
        let mut prefix_rc = RateChecker::from_config(config);
        if let Err(err) = write_all_to_stream_rated(
            client_stream,
            client_slice,
            &mut prefix_rc,
            RateCheckDirection::Client,
            config.http_timeout,
        )
        .await
        {
            // Both of this writer's stall paths surface as `TimedOut`,
            // which `is_peer_disconnect` deliberately excludes: the
            // rate-check failure and the `http_timeout` write stall (which
            // bumps `HTTP_TIMEOUT_CLIENT_BODY`). Pre-branch it so a slow or
            // stalled client stays `info` like hyper's rate-timeout sibling.
            info_or_warn!(
                err.kind() == ErrorKind::TimedOut || is_peer_disconnect(&err),
                "splice proxy: failed to write body prefix to client {} for {} from mirror {}; continuing cache-only:  {}",
                conn_details.client,
                conn_details.debname,
                conn_details.mirror,
                ErrorReport(&err)
            );
            prefix_client_failed = true;
        } else {
            metrics::BYTES_SERVED_SPLICE.increment_by(client_slice.len() as u64);
            rates.client_bytes_sent += client_slice.len() as u64;
        }
    }

    Ok(prefix_client_failed)
}

/// A failed body transfer, with the partial file's path guard handed back.
///
/// The two callers attribute a failure differently -- the connection's drive
/// through [`BodyTransferError::into_after_header`], the client-less
/// detached download through [`BodyTransferError::log_detached`] -- and both
/// wordings name the on-disk path, which only [`CacheTarget`] holds. Since
/// the barrier has already travelled into the body loop by then, the target
/// cannot come back whole: the `TempPath` alone travels, and dropping it
/// removes the partial exactly as before.
struct BodyTransferFailure {
    temppath: TempPath,
    err: BodyTransferError,
}

/// A completed body transfer ([`transfer_body`]): [`body::BodyOutcome`] with
/// the target folded back in (its barrier travelled through the body loop)
/// and the delivered byte count already added to the rate timestamps.
struct BodyTransferred {
    target: CacheTarget,
    /// Set when the first client was demoted to a file-serve task; the
    /// caller awaits it after consuming the target's barrier.
    demoted_handle: Option<DemotedClientHandle>,
    /// The client went away mid-body (as opposed to being demoted, or never
    /// having been attached).
    client_disconnected: bool,
}

/// Transfer the remaining `splice_count` body bytes after the prefix:
/// zero-copy `splice(2)` for a plain-TCP upstream, userspace read
/// plus tee+splice fan-out for userspace TLS. Both rate windows end here
/// when the loop ran.
///
/// `client_stream` is `None` for the client-less detached download, which
/// also passes a zero-length `range_plan` so the loops run cache-only.
#[expect(
    clippy::too_many_arguments,
    reason = "two call sites; the arguments are the body's geometry and the transfer's state"
)]
async fn transfer_body(
    upstream_guard: &mut UnconsumedBodyGuard<'_>,
    client_stream: Option<&TcpStream>,
    mut target: CacheTarget,
    resume_offset: u64,
    body_content_length: NonZero<u64>,
    splice_count: u64,
    range_plan: &ServeParams,
    rates: &mut RateTimestamps,
) -> Result<BodyTransferred, BodyTransferFailure> {
    if splice_count == 0 {
        return Ok(BodyTransferred {
            target,
            demoted_handle: None,
            client_disconnected: false,
        });
    }

    let body_offset: i64 = (resume_offset + body_content_length.get() - splice_count)
        .try_into()
        .expect("the body prefix + extra body is limited in size");

    // splice_file_start is the file offset where the splice region begins.
    let splice_file_start = resume_offset + body_content_length.get() - splice_count;
    let client_range_end = range_plan.content_end();
    let splice_file_end = splice_file_start + splice_count;
    // How many bytes to skip at the start of the splice region before sending to client.
    // Worked example: total file = 1000, resume_offset = 0, splice_file_start = 0,
    // splice_file_end = 1000, client Range: bytes=200-499 → client_range_start = 200,
    // client_range_len = 300, client_range_end = 500.
    //   client_skip = 200 - 0 = 200 (drop leading bytes before the range)
    //   client_send = min(500, 1000) - (0 + 200) = 300 (send exactly the range)
    // If the range ends past the splice region (e.g. due to a body prefix already
    // consumed), the min() clamps to splice_file_end and saturating_sub clamps at 0.
    let client_skip = range_plan.content_start.saturating_sub(splice_file_start);
    // How many bytes to send to client from within the splice region.
    let client_send = client_range_end
        .min(splice_file_end)
        .saturating_sub(splice_file_start + client_skip);
    let range_filter = SpliceRangeFilter {
        skip: client_skip,
        send: client_send,
    };

    // `target.dbarrier` is moved in by value: on success it's returned for the
    // rename step; on a structured rate-timeout it's already consumed into
    // `Aborted(MirrorDownloadRate)`; on any other io::Error it's dropped
    // inside the callee and the Drop impl records `AlreadyLoggedJustFail`.
    let xfer = BodyTransfer::new(
        client_stream,
        target.dbarrier,
        &range_filter,
        &target.temppath,
        splice_count,
        body_offset,
    );
    let outcome = if let Some(tcp) = upstream_guard.zero_copy() {
        // Zero-copy path for plain TCP
        splice_proxy_body(xfer, tcp, &target.tempfile).await
    } else {
        // TLS: userspace read, then direct cache write and client write
        splice_proxy_body_tls(xfer, upstream_guard, &target.tempfile).await
    };
    // Any body-transfer error leaves the upstream mid-message (fewer
    // than content_length bytes consumed), so the socket still holds
    // undelivered bytes. `upstream_guard` (still armed here) poisons
    // the connection on the early return so PoolGuard::drop discards it
    // rather than re-pooling it -- the next checkout would otherwise log
    // "pooled connection to ... has unexpected data; connecting fresh".
    //
    // The body helpers tag which party broke, so the caller can attribute
    // the failure instead of blaming the client for an upstream stall; the
    // partial-file guard travels with the error so both attribution sinks
    // can name the on-disk path.
    let BodyOutcome {
        dbarrier: returned_dbarrier,
        demoted_handle,
        client_disconnected,
        client_bytes,
    } = match outcome {
        Ok(outcome) => outcome,
        Err(err) => {
            return Err(BodyTransferFailure {
                temppath: target.temppath,
                err,
            });
        }
    };
    target.dbarrier = returned_dbarrier;
    // The splice body block ran: the upstream-rate and client-rate windows
    // both end here. The demoted-client case reassigns `t_client_done`
    // again after the file-serve task completes.
    rates.t_upstream_done = PreciseInstant::now();
    rates.t_client_done = rates.t_upstream_done;
    rates.client_bytes_sent += client_bytes;
    Ok(BodyTransferred {
        target,
        demoted_handle,
        client_disconnected,
    })
}

/// If the first client was demoted to file-serve, wait for the background
/// task to finish sending before returning control to the connection
/// handler (which may reuse the socket for keep-alive). No demotion means
/// the splice loop served the client itself (or there was no body to
/// splice) -- that's a success, not a failure.
async fn await_demoted_client(
    demoted_handle: Option<DemotedClientHandle>,
    rates: &mut RateTimestamps,
) -> bool {
    let Some(handle) = demoted_handle else {
        return true;
    };
    let succeeded = match handle.await {
        Ok(DeliveryResult::Success(bytes)) => {
            rates.client_bytes_sent += bytes;
            true
        }
        Ok(DeliveryResult::Failure(bytes)) => {
            rates.client_bytes_sent += bytes;
            false
        }
        Err(err) => {
            error!(
                "splice proxy: demoted client file-serve task panicked; treating the delivery as failed and closing the connection:  {}",
                ErrorReport(&err)
            );
            false
        }
    };
    // The demoted file-serve task is the last thing to write to the
    // client, so the client-rate window ends here.
    rates.t_client_done = PreciseInstant::now();
    succeeded
}

/// Body of [`splice_proxy`] after the originate check has succeeded: the
/// download as a sequence of phases. Kept as a separate fn returning
/// `Result<SpliceProxyOutcome, SpliceProxyError>` so the many early returns
/// scattered through the body do not need to be rewritten just because the
/// outer success type changed.
async fn splice_proxy_drive(
    client: ClientConn<'_>,
    conn_details: &ConnectionDetails,
    upstream_path: &str,
    appstate: &AppState,
    client_range: RangeRequestHeaders<'_>,
    init_tx: tokio::sync::watch::Sender<()>,
    status: Arc<tokio::sync::RwLock<ActiveDownloadStatus>>,
) -> Result<SpliceProxyOutcome, SpliceProxyError> {
    // The dial target: the host the client named (an alias is a real
    // mirror), never the canonical mirror the caches key on.
    let host_authority = conn_details.upstream_authority();
    // Capture the original (pre-redirect) client request path. A 301 redirect
    // in `plan_upstream_response` shadows `upstream_path` to the redirected
    // URL; the Origin row (`commit_and_record`) and
    // `handle_volatile_buffered_download` must carry the original path so
    // registry keys match across all backends (the hyper backend in
    // hyper_conn.rs always uses the client-request URI).
    // Strip the query so cache identity (registry keys, Origin rows) stays
    // path-only; the query still rides on the upstream GET line via
    // `upstream_path`. Matches the hyper backend.
    let original_uri_path = upstream_path
        .split_once('?')
        .map_or(upstream_path, |(path, _)| path);

    let ibarrier = InitBarrier::new(
        init_tx,
        &status,
        &appstate.active_downloads,
        conn_details,
        original_uri_path,
    );

    if reject_if_verify_throttled(client, conn_details).await? {
        return Ok(SpliceProxyOutcome::Served);
    }

    let mut resume = open_partial_resume(&ibarrier, conn_details).await?;

    let (volatile_cond, volatile_cache_path) =
        read_volatile_validators(conn_details).await?.unzip();

    // --- Prepare upstream connection ---
    // Dial the host the client named; `conn_details.mirror` is the
    // canonical cache identity, which may be an alias' main host.
    let mut exchange = standard_upstream_connect(
        &conn_details.upstream_mirror(),
        &host_authority,
        upstream_path,
        resume.offset,
        resume.if_range.as_deref(),
        volatile_cond.as_ref(),
        None,
    )
    .await
    .map_err(SpliceProxyError::Upstream)?;

    let plan = plan_upstream_response(
        &mut exchange,
        conn_details,
        &host_authority,
        upstream_path,
        &mut resume,
        volatile_cond.as_ref(),
        volatile_cache_path,
    )
    .await?;

    // The exchange is final: split it into the locals the rest of the
    // download uses.
    let conn_label = exchange.label();
    let UpstreamExchange {
        conn: mut upstream,
        response: upstream_resp,
        header_buf,
        header_end,
        reused: _,
    } = exchange;

    // Answered by the upstream (fresh body or a 304): this is the point the
    // request's Origin row is earned.
    if plan.is_answered() {
        conn_details.record_origin();
    }

    let (total_content_length, body_content_length, resume_offset) = match plan {
        DownloadPlan::NotModified(cache_path) => {
            // Upstream confirms the cached copy is still current: refresh the
            // freshness window and serve the cached file via sendfile.
            debug!(
                "splice proxy: upstream returned 304 for {} from mirror {}, serving cached file",
                conn_details.debname, conn_details.mirror
            );

            // Pool the upstream connection back (304 has no body).
            if upstream_resp.connection_close {
                upstream.unset_poolable();
            }
            drop(upstream);

            return serve_volatile_304_via_sendfile(
                client,
                conn_details,
                &cache_path,
                client_range,
                ibarrier,
                "post-304 invalid response",
            )
            .await
            .map(|()| SpliceProxyOutcome::Served);
        }
        DownloadPlan::Passthrough => {
            relay_passthrough(
                &mut upstream,
                client,
                conn_details,
                &upstream_resp,
                &header_buf,
                header_end,
            )
            .await?;
            return Ok(SpliceProxyOutcome::Served);
        }
        DownloadPlan::Reject(reason) => {
            reject_upstream_response(&mut upstream, client, conn_details, reason).await?;
            return Ok(SpliceProxyOutcome::Served);
        }
        DownloadPlan::Download {
            total: ContentLength::Exact(total),
            body: ContentLength::Exact(body),
            resume_offset,
        } => {
            if resume_offset > 0 {
                #[expect(clippy::cast_precision_loss, reason = "only for display purpose")]
                let remaining_percent = body.get() as f32 / total.get() as f32 * 100.0;
                info!(
                    "splice proxy: resuming download of {} from mirror {} at {} ({} ({:.1}%) remaining of {} total)",
                    conn_details.debname,
                    conn_details.mirror,
                    HumanFmt::Size(resume_offset),
                    HumanFmt::Size(body.get()),
                    remaining_percent,
                    HumanFmt::Size(total.get())
                );
            }
            (total, body, resume_offset)
        }
        // A volatile file without a usable Content-Length (chunked or
        // close-delimited): length-delimited bodies are spliced, anything
        // else is buffered.
        DownloadPlan::Download { .. } => {
            return handle_volatile_buffered_download(
                &mut upstream,
                client,
                conn_details,
                original_uri_path,
                &upstream_resp,
                &header_buf[header_end..],
                ibarrier,
                client_range,
                conn_label,
            )
            .await
            .map(|()| SpliceProxyOutcome::Served);
        }
    };

    // Committed to splicing a length-delimited body: keep the upstream out of
    // the pool for the whole "body not yet drained" window, so no early return
    // below can leave a half-read connection re-poolable. Defused via
    // `consumed()` once the body is fully read.
    let mut upstream_guard = UnconsumedBodyGuard::new(&mut upstream);

    // `If-Range` compares against the validators this response carries.
    let cache_time = upstream_resp
        .last_modified
        .as_deref()
        .and_then(HttpDate::parse)
        .unwrap_or(HttpDate::UNIX_EPOCH);
    let Some(range_plan) = resolve_client_range(
        client,
        conn_details,
        client_range,
        total_content_length.get(),
        cache_time,
        upstream_resp.etag.as_deref(),
        "416 response",
    )
    .await?
    else {
        return Ok(SpliceProxyOutcome::Served);
    };

    let Some(mut target) = prepare_cache_target(
        client,
        conn_details,
        &upstream_resp,
        resume.partial,
        resume_offset,
        total_content_length,
        ibarrier,
        "quota 503",
    )
    .await?
    else {
        return Ok(SpliceProxyOutcome::Served);
    };

    let body_prefix = &header_buf[header_end..];
    let Some(splice_count) = splice_body_count(
        &mut upstream_guard,
        client,
        conn_details,
        body_content_length,
        body_prefix,
    )
    .await?
    else {
        return Ok(SpliceProxyOutcome::Served);
    };

    // The parallel-download hack, gated here: quota, the resume-size check,
    // the 416 and the framing rejections have all had their say, the total
    // size is known and the registry entry exists, so a nudged request can
    // be late-joined by its own retry. Hand the client a `Retry-After` and
    // let a detached, client-less task finish the download; the retry
    // attaches to it through `attach()` on the same keep-alive connection.
    // The gate, the head and the wording are shared with the hyper backend
    // (`parallel_hack.rs`). Range and resumed requests are nudged too, for
    // that parity: the retry's Range is honoured by the late-joiner path.
    let config = global_config();
    if should_nudge(
        config,
        conn_details.cached_flavor(),
        || appstate.active_downloads.len(),
        total_content_length,
        &mut rand::rng(),
    ) {
        log_nudge(conn_details, config, "splice proxy: ");
        // The upstream connection moves into the task, which re-arms its own
        // `UnconsumedBodyGuard` as the very first thing it does once polled;
        // defusing this one here just hands ownership across cleanly.
        upstream_guard.consumed();
        drop(upstream_guard);
        // Spawn before writing the nudge, as the hyper backend does: a
        // failed nudge write closes the connection, but the download still
        // lands in the cache.
        DetachedDownload {
            upstream,
            header_buf,
            header_end,
            target,
            conn_details: conn_details.clone(),
            original_uri_path: original_uri_path.to_owned(),
            conn_label,
            total_content_length,
            body_content_length,
            resume_offset,
            splice_count,
            request_sent_at: upstream_resp
                .request_sent_at
                .unwrap_or_else(PreciseInstant::now),
        }
        .spawn();
        // `REQUESTS_SPLICE` stays unbumped -- no splice response was served;
        // `write_to` records the client-status metric for the nudge itself.
        return nudge_head(config)
            .write_to(
                client.stream,
                client.version,
                client.action,
                WireBody::Inline(NUDGE_BODY),
            )
            .await
            .map(|()| SpliceProxyOutcome::Served)
            .map_err(SpliceProxyError::client("parallel hack nudge"));
    }

    let start = PreciseInstant::now();

    // Per-request rate-logging timestamps; the upstream-rate window ends
    // here in case the splice loop never runs.
    let mut rates = RateTimestamps::new(upstream_resp.request_sent_at.unwrap_or(start));

    log_download_start(
        conn_details,
        conn_label,
        resume_offset,
        total_content_length,
        false,
    );

    // Cork the socket to coalesce headers + body prefix into fewer TCP segments
    let cork = CorkGuard::new_optional(client.stream);

    rates.t_client_first = write_splice_response_headers(
        client,
        conn_details,
        &upstream_resp,
        &range_plan,
        "response headers",
    )
    .await?;

    rates.client_bytes_sent +=
        send_resumed_prefix(client.stream, &target.temppath, &range_plan, resume_offset).await?;

    let prefix_client_failed = write_body_prefix(
        client.stream,
        conn_details,
        &mut target,
        body_prefix,
        &range_plan,
        resume_offset,
        &mut rates,
    )
    .await?;

    // Client-rate-window end after the prefix write; covers
    // the case where the splice loop never runs (whole body in the prefix).
    // Reassigned after the splice body block and the demoted file-serve task.
    rates.t_client_done = PreciseInstant::now();

    let BodyTransferred {
        target,
        demoted_handle,
        client_disconnected: body_client_disconnected,
    } = transfer_body(
        &mut upstream_guard,
        Some(client.stream),
        target,
        resume_offset,
        body_content_length,
        splice_count,
        &range_plan,
        &mut rates,
    )
    .await
    .map_err(|BodyTransferFailure { temppath, err }| {
        err.into_after_header("splice body transfer", &temppath)
    })?;

    // Uncork only now. The client splice in `body.rs::tee_and_splice` sets
    // SPLICE_F_MORE on every chunk, including the last, and SPLICE_F_MORE
    // becomes MSG_MORE: the kernel holds the final sub-MSS segment until the
    // peer ACKs, which for a client with nothing left to send is its delayed
    // ACK, up to 200 ms later. The uncork is what flushes that tail, so the
    // guard has to outlive the body — the same lifetime `volatile.rs` keeps.
    drop(cork);

    // The full upstream body is now drained: either the splice loop consumed
    // exactly `splice_count` bytes, or `splice_count` was 0 because the whole
    // body arrived in the prefix. The client-write outcome is
    // irrelevant to poolability — the download always drains upstream fully.
    // Defuse the poison guard and release its borrow before dropping upstream.
    upstream_guard.consumed();
    drop(upstream_guard);

    // PoolGuard::drop returns the connection to pool if still poolable.
    // Drop it now before the sync+rename to free the upstream socket promptly.
    drop(upstream);

    // Commit the finished body to the cache. On failure the body was
    // already fully delivered to the client; this only leaves the cache
    // without the file, and we still finish the client-facing bookkeeping
    // (await the demoted task, count the delivery) before returning.
    let committed = commit_and_record(
        target,
        conn_details,
        original_uri_path,
        total_content_length,
        start,
    )
    .await;

    let demoted_client_succeeded = await_demoted_client(demoted_handle, &mut rates).await;

    let client_succeeded =
        !prefix_client_failed && !body_client_disconnected && demoted_client_succeeded;

    // Only log a completion "…cached…" line when the file actually landed in
    // the cache; the commit-failure path already logged an ERROR (rename) or
    // commit() logged the mismatch/verify failure internally.
    if committed.is_some() {
        log_splice_completion(
            conn_details,
            conn_label,
            &rates,
            body_content_length.get(),
            resume_offset,
            if client_succeeded {
                CompletionClient::Served {
                    bytes: range_plan.content_length,
                }
            } else {
                CompletionClient::Lost
            },
        );
    }

    if !client_succeeded {
        // The actual failure (prefix-write, body splice, or demoted task)
        // was already logged at its source, and the download itself ran to
        // completion; report the lost client as the outcome it is rather
        // than as an error, so the outer arm closes the connection without
        // a duplicate client-error log line.
        return Ok(SpliceProxyOutcome::ClientLost);
    }

    metrics::SERVED_SPLICE.increment();
    metrics::SERVED_TOTAL.increment();

    if let Some(elapsed) = committed {
        record_delivery(
            conn_details,
            total_content_length,
            elapsed,
            range_plan.is_partial(),
        )
        .await;
    }

    Ok(SpliceProxyOutcome::Served)
}

/// Successful outcomes of [`splice_proxy`]. `Concurrent` is an alternate
/// success path, not an error: another download for the same key won the
/// originate race, and the carried `status` lets the caller serve the client
/// from the in-flight partial via the sendfile backend without falling back
/// to hyper. Late-joiner accounting was already performed inside
/// [`crate::active_downloads::ActiveDownloads::originate`].
pub(crate) enum SpliceProxyOutcome {
    Served,
    /// The download ran to completion (cached or not), but the client's
    /// delivery failed after the response headers went out -- the body
    /// prefix write, the splice loop, or the demoted file-serve task -- and
    /// that source logged it. The caller closes the connection without a new
    /// status and without logging again.
    ClientLost,
    Concurrent {
        status: Arc<tokio::sync::RwLock<ActiveDownloadStatus>>,
    },
    /// Origination refused by the `max_upstream_downloads` cap
    /// (`OriginateOutcome::AtCapacity`); nothing was written to the client.
    /// The sendfile caller answers with the canonical 503
    /// (`"Too many concurrent upstream downloads"`) — not an error, the
    /// connection stays usable.
    AtCapacity {
        max: NonZero<usize>,
    },
}

/// Errors out of the splice proxy paths. Every variant reaching a
/// connection-level outcome goes through the single outer arm,
/// `sendfile_conn::splice_error_outcome`, whose `match` is exhaustive on
/// purpose: a new variant is a compile error there, and its logging policy is
/// decided here, on the variant, not in prose elsewhere.
///
/// The payload encodes who logs. An `io::Error` (plus the `phase` tag naming
/// the response phase that broke, e.g. `"response headers"`,
/// `"416 response"`, so the operator does not grep-walk the source) means the
/// outer arm logs it -- it holds the subsystem prefix and the subject. A
/// [`Logged`] means the throw site already did, because the context that
/// makes the line actionable (the on-disk path, the upstream authority and
/// attempt count) exists only there; the outer arm maps it silently. There is
/// no third case: a variant is never logged twice, and never not at all.
pub(crate) enum SpliceProxyError {
    /// The upstream connect, request or header read failed before anything
    /// was written to the client. Logged at the throw site (once-gated WARN,
    /// then INFO, with the authority, path and attempt count); the outer arm
    /// answers `502 Bad Gateway` / `"Upstream Error"` silently. The carried
    /// transport error is for callers that report the cause elsewhere
    /// (cleanup's decision log).
    Upstream(UpstreamFailure),
    /// A write to the client failed before the response headers went out.
    /// Logged at the outer arm with the `is_peer_disconnect` split (INFO for
    /// a peer disconnect, WARN otherwise); the connection is closed without a
    /// new status.
    Client {
        phase: &'static str,
        err: std::io::Error,
    },
    /// A cache-file operation failed before the response headers went out.
    /// Logged at the throw site (ERROR naming the path, plus the
    /// `CACHE_IO_FAILURE` / `CACHE_NON_REGULAR` bump); the outer arm answers
    /// `500 Internal Server Error` / `"Cache Access Failure"` silently.
    Cache(Logged),
    /// An I/O failure after the response headers were written. The client
    /// already holds a 200/206 header, so the outer arm closes the
    /// connection without a new status; `side` says which of the parties
    /// broke and carries what that party's logging policy needs.
    AfterHeader {
        phase: &'static str,
        side: AfterHeaderSide,
    },
}

impl SpliceProxyError {
    /// [`Self::Client`] for a failed write in `phase`, as a `map_err` closure.
    fn client(phase: &'static str) -> impl FnOnce(std::io::Error) -> Self {
        move |err| Self::Client { phase, err }
    }

    /// [`Self::AfterHeader`] on the client side for a failed write in
    /// `phase`, as a `map_err` closure.
    fn after_header_client(phase: &'static str) -> impl FnOnce(std::io::Error) -> Self {
        move |err| Self::AfterHeader {
            phase,
            side: AfterHeaderSide::Client(err),
        }
    }
}

/// A failed upstream connect / request / header read, see
/// [`SpliceProxyError::Upstream`]. `err` is the transport cause; `logged`
/// proves the throw site already reported it with its context.
pub(crate) struct UpstreamFailure {
    #[cfg_attr(
        feature = "hyper",
        expect(
            dead_code,
            reason = "read by the hyper-less `cleanup_upstream_fetch`; with hyper, cleanup fetches through hyper instead"
        )
    )]
    pub(crate) err: std::io::Error,
    pub(crate) logged: Logged,
}

/// The party that broke after the response headers went out
/// ([`SpliceProxyError::AfterHeader`]). Mirrors [`body::BodyFailureSide`], but each
/// side carries what its logging policy needs: the peer sides hand the error
/// to the outer arm, the proxy-local sides own the on-disk path and log at the
/// throw site.
pub(crate) enum AfterHeaderSide {
    /// The mirror stalled, hung up, or fell below `min_download_rate`
    /// mid-body. Logged at the outer arm at plain WARN: unlike a client
    /// hang-up there is no benign case, and the throw sites already bumped
    /// their dedicated counter (`HTTP_TIMEOUT_UPSTREAM_READ`,
    /// `RATE_LIMIT_UPSTREAM`, `UPSTREAM_PROTOCOL_VIOLATION`), so the line is
    /// counter-backed and bounded to one per connection.
    Upstream(std::io::Error),
    /// The client socket. Logged at the outer arm with the
    /// `is_peer_disconnect` split (INFO for a peer disconnect, WARN
    /// otherwise).
    Client(std::io::Error),
    /// A cached-file syscall (tempfile write, rename, partial-file reopen,
    /// the `splice` into the cache fd). Logged at the throw site (ERROR
    /// naming the path, plus `CACHE_IO_FAILURE`); the outer arm is silent.
    Cache(Logged),
    /// Another proxy-side resource: the internal splice pipes, or the fd
    /// duplication behind the demoted file-serve task. Logged at the throw
    /// site (ERROR, no metric -- not a cached-file syscall); the outer arm is
    /// silent.
    Proxy(Logged),
}

#[cfg(test)]
mod tests {
    use super::http::parse_upstream_response;

    use super::*;
    use crate::cache_conditional::RangeNotSatisfiable;

    #[test]
    fn client_range_plan_resolves_every_parsed_range() {
        let whole = || ServeParams {
            content_range: None,
            content_start: 0,
            content_length: 1000,
        };
        assert_eq!(ServeParams::from_parsed(None, 1000), Ok(whole()));
        assert_eq!(
            ServeParams::from_parsed(Some(ParsedRange::Invalid), 1000),
            Ok(whole())
        );
        assert_eq!(
            ServeParams::from_parsed(Some(ParsedRange::IfRangeFailed), 1000),
            Ok(whole())
        );
        assert_eq!(
            ServeParams::from_parsed(Some(ParsedRange::NotSatisfiable), 1000),
            Err(RangeNotSatisfiable)
        );
        assert!(!whole().is_partial());
        assert_eq!(whole().content_end(), 1000);
        assert_eq!(whole().http_status(), StatusCode::OK);
        assert_eq!(whole().status_line(), "200 OK");

        let partial = ServeParams::from_parsed(
            Some(ParsedRange::Satisfiable {
                content_range: "bytes 200-499/1000".to_owned(),
                start: 200,
                length: 300,
            }),
            1000,
        )
        .expect("satisfiable");
        assert_eq!(
            partial,
            ServeParams {
                content_range: Some("bytes 200-499/1000".to_owned()),
                content_start: 200,
                content_length: 300,
            }
        );
        assert!(partial.is_partial());
        assert_eq!(partial.content_end(), 500);
        assert_eq!(partial.http_status(), StatusCode::PARTIAL_CONTENT);
        assert_eq!(partial.status_line(), "206 Partial Content");
    }

    /// Pins the wire bytes of the splice response head shared by the
    /// streaming drive and the buffered volatile path (header order included).
    #[test]
    fn splice_response_head_renders_the_pinned_bytes() {
        let date = "Fri, 02 Jan 2026 00:00:00 GMT";

        let headers = b"HTTP/1.1 200 OK\r\n\
                        Content-Length: 1000\r\n\
                        Last-Modified: Thu, 01 Jan 2025 00:00:00 GMT\r\n\
                        ETag: \"abc\"\r\n\
                        \r\n";
        let resp =
            parse_upstream_response(headers, headers.len(), "test.mirror").expect("should parse");
        let whole = ServeParams::from_parsed(None, 1000).expect("no range");
        let head = render_splice_response_head(
            ConnectionVersion::Http11,
            ConnectionAction::KeepAlive,
            &resp,
            &whole,
            "application/vnd.debian.binary-package",
            date,
        );
        assert_eq!(
            head,
            format!(
                "HTTP/1.1 200 OK\r\n\
                 Date: {date}\r\n\
                 Via: {APP_VIA}\r\n\
                 Connection: keep-alive\r\n\
                 Content-Length: 1000\r\n\
                 Content-Type: application/vnd.debian.binary-package\r\n\
                 Last-Modified: Thu, 01 Jan 2025 00:00:00 GMT\r\n\
                 ETag: \"abc\"\r\n\
                 Accept-Ranges: bytes\r\n\
                 Age: 0\r\n\
                 \r\n"
            )
        );

        let headers = b"HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\n";
        let resp =
            parse_upstream_response(headers, headers.len(), "test.mirror").expect("should parse");
        let partial = ServeParams::from_parsed(
            Some(ParsedRange::Satisfiable {
                content_range: "bytes 200-499/1000".to_owned(),
                start: 200,
                length: 300,
            }),
            1000,
        )
        .expect("satisfiable");
        let head = render_splice_response_head(
            ConnectionVersion::Http10,
            ConnectionAction::Close,
            &resp,
            &partial,
            "text/plain",
            date,
        );
        assert_eq!(
            head,
            format!(
                "HTTP/1.0 206 Partial Content\r\n\
                 Date: {date}\r\n\
                 Via: {APP_VIA}\r\n\
                 Connection: close\r\n\
                 Content-Length: 300\r\n\
                 Content-Type: text/plain\r\n\
                 Accept-Ranges: bytes\r\n\
                 Age: 0\r\n\
                 Content-Range: bytes 200-499/1000\r\n\
                 \r\n"
            )
        );
    }
}
