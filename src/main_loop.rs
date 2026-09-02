use std::{
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    num::NonZero,
    time::Duration,
};

use coarsetime::Instant;
#[cfg(feature = "hyper")]
use futures_util::StreamExt as _;
#[cfg(feature = "hyper")]
use http::{Method, Request, Uri, header::USER_AGENT};
#[cfg(feature = "hyper")]
use http_body_util::Empty;
use tokio::{net::TcpListener, signal::unix::SignalKind};
use tracing::{debug, error, info, trace, warn};

#[cfg(not(feature = "sendfile"))]
use crate::hyper_conn::handle_hyper_connection;
#[cfg(feature = "hyper")]
use crate::hyper_conn::{HttpClient, request_with_retry};
#[cfg(feature = "sendfile")]
use crate::sendfile_conn;
use crate::{
    AppState, DB_DRAIN_TIMEOUT, OUTPUT_LOG_FILE, RUNTIMEDETAILS,
    active_downloads::ActiveDownloads,
    cache_metadata,
    cache_paths::CachePaths,
    cleanup::{
        CLEANUP_INTERVAL_SECS, FIRST_CLEANUP_DELAY_SECS, set_next_cleanup_epoch, task_cleanup,
    },
    client_counter,
    client_info::ClientInfo,
    database::Database,
    database_task::{self, db_loop},
    deb_mirror,
    error::ErrorReport,
    flat_blocklist, global_config,
    healthcheck::{self, filesystem_space},
    humanfmt::HumanFmt,
    metrics,
    task_cache_scan::{CacheScanError, task_cache_scan},
    warn_once_or_debug, warn_once_or_info,
};
#[cfg(feature = "hyper")]
use crate::{build_info::APP_USER_AGENT, scheme_cache};

/// One-line accounting emitted on every shutdown path: what the process did
/// over its lifetime, and what it is dropping on the floor. Without it a
/// stopped daemon leaves no record of whether it was in the middle of
/// serving anything when the signal arrived, which is the first question
/// after an unexpected restart -- and the counters behind the dashboard die
/// with the process.
fn log_shutdown_summary(signal: &str, active_downloads: &ActiveDownloads) {
    let rd = RUNTIMEDETAILS.get().expect("global set in main()");
    let uptime = (time::OffsetDateTime::now_utc() - rd.start_time).unsigned_abs();

    let bytes_served = [
        metrics::BYTES_SERVED_MMAP.get(),
        metrics::BYTES_SERVED_SENDFILE.get(),
        metrics::BYTES_SERVED_SPLICE.get(),
        metrics::BYTES_SERVED_COPY.get(),
        metrics::BYTES_SERVED_CHANNEL.get(),
        metrics::BYTES_SERVED_PASSTHROUGH.get(),
    ]
    .into_iter()
    .fold(0u64, u64::saturating_add);

    info!(
        "{signal} shutdown summary after {}: {} requests, {} fully served, {} cache hits, {} misses, {} served to clients, {} fetched upstream; dropping {} client connections, {} client downloads, {} upstream downloads",
        HumanFmt::Time(uptime),
        metrics::REQUESTS_TOTAL.get(),
        metrics::SERVED_TOTAL.get(),
        metrics::CACHE_HITS.get(),
        metrics::CACHE_MISSES.get(),
        HumanFmt::Size(bytes_served),
        HumanFmt::Size(metrics::BYTES_DOWNLOADED_UPSTREAM.get()),
        client_counter::connected_clients(),
        client_counter::active_client_downloads(),
        active_downloads.len(),
    );
}
/// Why [`main_loop`] gave up.  Every throw site has already logged the cause
/// with its context, so `Display` only re-renders the wrapped error (through
/// [`ErrorReport`], with no `source()`) for `main`'s final
/// `Failed to run apt-cacher-rs` line.
#[derive(Debug, thiserror::Error)]
pub(crate) enum MainLoopError {
    /// Startup-time database access (open, schema init, row cleanup, mirror
    /// reads) failed.
    #[error("{}", ErrorReport(.0))]
    Database(sqlx::Error),
    /// Signal registration, listener bind, or accept failed.
    #[error("{}", ErrorReport(.0))]
    Io(std::io::Error),
    /// The startup cache scan failed while a disk quota is configured, so
    /// the quota could not be enforced.
    #[error("{}", ErrorReport(.0))]
    CacheScan(CacheScanError),
}

pub(crate) async fn main_loop(
    #[cfg(feature = "hyper")] https_client: HttpClient,
) -> Result<(), MainLoopError> {
    let config = global_config();

    let database = Database::connect(&config.database_path, config.database_slow_timeout)
        .await
        .inspect_err(|err| {
            error!(
                "Failed to open database `{}`; aborting startup:  {}",
                config.database_path.display(),
                ErrorReport(err)
            );
        })
        .map_err(MainLoopError::Database)?;

    database
        .init_tables()
        .await
        .inspect_err(|err| {
            error!(
                "Failed to initialize database `{}`; aborting startup:  {}",
                config.database_path.display(),
                ErrorReport(err)
            );
        })
        .map_err(MainLoopError::Database)?;

    database
        .cleanup_invalid_rows()
        .await
        .inspect_err(|err| {
            error!(
                "Failed to clean up invalid database rows; aborting startup:  {}",
                ErrorReport(err)
            );
        })
        .map_err(MainLoopError::Database)?;

    // Fold mirror rows an earlier version wrote under an alias host into
    // their main row before anything reads them: the startup scan, the
    // flat blocklist and cleanup all key on the canonical host now.
    match database.merge_alias_rows(&config.aliases).await {
        Ok(0) => {}
        Ok(merged) => {
            info!("Folded {merged} mirror rows written under alias hosts into their main rows");
        }
        Err(err) => {
            error!(
                "Failed to fold alias mirror rows into their main rows; aborting startup:  {}",
                ErrorReport(&err)
            );
            return Err(MainLoopError::Database(err));
        }
    }

    // Seed the per-host flat-layout collision blocklist from any
    // pre-existing structured mirrors whose `mirror_path` starts with
    // `flat/` (or equals `flat`).  Those hosts get flat caching disabled
    // — see `flat_blocklist` for the rationale.
    //
    // Both failure modes here are startup-fatal: a DB read error would
    // leave the blocklist empty and silently re-allow flat caching at
    // collision sites (propagated via `?` after logging), and a double-
    // init is a programmer error in main-loop ordering (the `.expect`
    // inside `flat_blocklist::init` panics).
    flat_blocklist::init(&database)
        .await
        .inspect_err(|err| {
            error!(
                "Failed to load flat-collision mirrors from the database; aborting startup:  {}",
                ErrorReport(err)
            );
        })
        .map_err(MainLoopError::Database)?;

    // Database background task
    let (db_task_tx, db_task_rx) = tokio::sync::mpsc::channel(config.db_channel_capacity.get());
    let (db_shutdown_tx, db_shutdown_rx) = tokio::sync::watch::channel(false);
    let db_join = {
        let database = database.clone();
        let flush_max_count = config.db_batch_flush_max_count.get();
        let flush_interval = Duration::from_secs(config.db_batch_flush_interval_secs.get());
        tokio::task::spawn(db_loop(
            database,
            db_task_rx,
            db_shutdown_rx,
            flush_max_count,
            flush_interval,
        ))
    };
    database_task::DB_TASK_QUEUE_SENDER
        .set(db_task_tx)
        .expect("DB task queue sender initialized once");

    // Process-local cache for cached-file ETag / Last-Modified xattrs.
    cache_metadata::init().expect("cache metadata store initialized once");

    // Migration warning: scan the existing `mirrors_v2` rows for paths
    // containing a `RESERVED_MIRROR_PATH_SEGMENTS` segment.  Pre-existing
    // rows still load via `get_mirrors`, but the validator now rejects
    // them on insert — flag them once at startup so an operator can
    // investigate (cleanup walks against e.g. `<host>/by-hash` would
    // otherwise collide with the layout plumbing for that mirror's
    // sibling).
    let mirrors = database
        .get_mirrors()
        .await
        .inspect_err(|err| {
            error!(
                "Failed to read the mirror rows for the reserved-segment migration check; aborting startup:  {}",
                ErrorReport(err)
            );
        })
        .map_err(MainLoopError::Database)?;

    for mirror in &mirrors {
        if deb_mirror::mirror_path_has_reserved_segment(&mirror.path) {
            warn!(
                "Pre-existing mirror row {}/{} uses a reserved path segment (one of {:?}); cleanup walks may collide with cache plumbing, so investigate and consider removing the row",
                mirror.host,
                mirror.path,
                deb_mirror::RESERVED_MIRROR_PATH_SEGMENTS,
            );
        }
    }

    // Migration warning: the pre-fix flat layout cached every flat-repo
    // file under `<cache>/<host>/<mirror_path>/flat/...`.  Post-fix lookups
    // go to `<cache>/<host>/flat/<mirror_path>/...`, so those legacy
    // directories are now unreachable disk waste.  Probe each registered
    // mirror's legacy flat dir and warn so the operator can reclaim
    // space; we deliberately do not remove anything automatically because
    // a misconfigured alias change could otherwise wipe live cache.
    let paths = CachePaths::new(&config.cache_directory);
    for mirror in &mirrors {
        let legacy_flat = paths.legacy_flat_dir(mirror.site());
        match tokio::fs::symlink_metadata(&legacy_flat).await {
            Ok(md) if md.file_type().is_dir() => {
                warn!(
                    "Legacy pre-fix flat cache directory `{}` is now unreachable (flat files moved to `<host>/flat/<mirror_path>/`); inspect and remove to reclaim disk space",
                    legacy_flat.display(),
                );
            }
            Ok(_) | Err(_) => {}
        }
    }

    // Initial cache scan. Awaited before the listener binds: the quota is
    // enforced against this total, so a download admitted earlier would be
    // checked against an empty cache, and one committing mid-scan would be
    // counted twice.
    {
        let scan_start = Instant::now();
        match task_cache_scan(&database).await {
            Ok(totals) => {
                let scanned = HumanFmt::Time(scan_start.elapsed().into());
                let cache_size = totals.bytes;
                let files = totals.files;
                let rd = RUNTIMEDETAILS.get().expect("global set in main()");

                rd.cache_quota.record_startup_scan(cache_size);

                // The quota is only the bound this daemon enforces; what
                // actually runs out is the filesystem -- and it can run
                // out of inodes long before it runs out of bytes, which
                // is exactly the ENOSPC an operator cannot explain from
                // a byte figure alone. A failed statvfs is already
                // warned about inside `filesystem_space`.
                let space = filesystem_space(&rd.config.cache_directory).await;
                let free = match space {
                    Some(space) => format!(
                        "free disk space: {}, free inodes: {}",
                        HumanFmt::Size(space.free_bytes),
                        match space.inodes {
                            Some(inodes) => format!("{} of {}", inodes.free, inodes.total),
                            None => "unlimited".to_owned(),
                        }
                    ),
                    None => "free disk space: unknown".to_owned(),
                };

                match rd.config.disk_quota.map(NonZero::get) {
                    Some(quota) if cache_size > quota => {
                        warn!(
                            "Startup cache size of {} in {files} files exceeds quota {} ({free}, scanned in {scanned}); downloads are rejected as over quota until cleanup frees space",
                            HumanFmt::Size(cache_size),
                            HumanFmt::Size(quota)
                        );
                    }
                    Some(quota) => {
                        info!(
                            "Startup cache size: {} in {files} files (quota={}, {free}, scanned in {scanned})",
                            HumanFmt::Size(cache_size),
                            HumanFmt::Size(quota)
                        );
                    }
                    None => {
                        info!(
                            "Startup cache size: {} in {files} files (quota=unlimited, {free}, scanned in {scanned})",
                            HumanFmt::Size(cache_size)
                        );
                    }
                }

                // Inode exhaustion produces an ENOSPC that no byte
                // figure explains; same floors as the readiness check.
                if let Some(detail) = healthcheck::low_inodes_detail(space.and_then(|s| s.inodes)) {
                    warn!(
                        "Cache filesystem `{}` is running out of inodes ({detail}); cache writes will fail with ENOSPC while disk space still looks free",
                        rd.config.cache_directory.display()
                    );
                }
            }
            Err(err) => {
                if config.disk_quota.is_some() {
                    error!(
                        "Failed to scan the cache directory at startup after {}; a disk quota is configured and cannot be enforced without the scanned size, aborting startup:  {}",
                        HumanFmt::Time(scan_start.elapsed().into()),
                        ErrorReport(&err)
                    );
                    return Err(MainLoopError::CacheScan(err));
                }
                error!(
                    "Failed to scan the cache directory at startup after {}; no disk quota is configured, the accounted cache size stays unset until the next cleanup reconcile:  {}",
                    HumanFmt::Time(scan_start.elapsed().into()),
                    ErrorReport(&err)
                );
            }
        }
    }

    // Scheme cache initialization task (hyper backend only — the splice-only
    // build has no upstream HTTP client to issue the warm-up HEAD requests).
    #[cfg(feature = "hyper")]
    {
        let database = database.clone();
        let client = https_client.clone();

        tokio::task::spawn(async move {
            // Use buffer_unordered to limit concurrent requests and avoid thundering herd
            const MAX_CONCURRENT_REQUESTS: usize = 10;
            // Do not initialize stale mirrors
            const STALE_THRESHOLD: Duration = Duration::from_hours(30 * 24);

            debug!("Scheme cache initialization task started");

            let mut mirrors = match database.get_recent_mirrors(STALE_THRESHOLD).await {
                Ok(m) => m,
                Err(err) => {
                    metrics::DB_OPERATION_FAILED.increment();
                    error!(
                        "Failed to read the mirror list for the scheme-cache warm-up; the scheme cache starts empty and every host's scheme is decided on first use:  {}",
                        ErrorReport(&err)
                    );
                    return;
                }
            };

            mirrors
                .sort_unstable_by(|a, b| a.host.cmp(&b.host).then_with(|| a.port().cmp(&b.port())));
            mirrors.dedup_by(|a, b| a.host == b.host && a.port() == b.port());

            futures_util::stream::iter(mirrors)
                .map(|mirror| {
                    let client = client.clone();
                    async move {
                        let authority = mirror.format_authority();

                        let uri = Uri::builder()
                            .scheme("http")
                            .authority(authority.as_ref())
                            .path_and_query("/")
                            .build()
                            .expect("Valid URI");

                        let request = Request::builder()
                            .method(Method::HEAD)
                            .uri(uri)
                            .header(USER_AGENT, APP_USER_AGENT)
                            .body(Empty::new())
                            .expect("Valid request");

                        match request_with_retry(&client, request).await {
                            Ok((response, _parts)) => {
                                if response.status().is_server_error() {
                                    warn!(
                                        "Scheme-cache warm-up request to host {authority} returned server error {}; ignoring the response, only the connection outcome seeds the scheme cache",
                                        response.status()
                                    );
                                } else {
                                    // ignore response, we just care about connection success
                                    trace!(
                                        "Response for host {authority} of initial scheme cache request:  {response:?}"
                                    );
                                }
                            }
                            Err(err) => {
                                // request_with_retry() has already logged the error
                                debug!("Failed to query host {authority} to initialize scheme cache:  {}", ErrorReport(&err));
                            }
                        }
                    }
                })
                .buffer_unordered(MAX_CONCURRENT_REQUESTS)
                .collect::<Vec<_>>()
                .await;

            trace!("Scheme cache:  {}", scheme_cache::debug_contents());

            debug!("Scheme cache initialization task finished");
        });
    }

    let mut term_signal =
        tokio::signal::unix::signal(SignalKind::terminate()).map_err(MainLoopError::Io)?;
    let mut usr1_signal =
        tokio::signal::unix::signal(SignalKind::user_defined1()).map_err(MainLoopError::Io)?;
    let mut usr2_signal =
        tokio::signal::unix::signal(SignalKind::user_defined2()).map_err(MainLoopError::Io)?;

    // The displayed "Next Cleanup" epoch is advanced from now() on each tick;
    // the underlying Tokio interval schedules from the original baseline
    // instead, so under sustained backpressure the displayed value can drift
    // a few seconds ahead of the real next tick. Accepted limitation.
    let first_cleanup = tokio::time::Instant::now() + Duration::from_secs(FIRST_CLEANUP_DELAY_SECS);
    let mut cleanup_interval =
        tokio::time::interval_at(first_cleanup, Duration::from_secs(CLEANUP_INTERVAL_SECS));
    set_next_cleanup_epoch(
        time::OffsetDateTime::now_utc().unix_timestamp()
            + i64::try_from(FIRST_CLEANUP_DELAY_SECS)
                .expect("FIRST_CLEANUP_DELAY_SECS fits in i64"),
    );

    let appstate = AppState {
        database,
        #[cfg(feature = "hyper")]
        https_client,
        active_downloads: ActiveDownloads::new(),
    };

    let mut addr = SocketAddr::from((config.bind_addr, config.bind_port.get()));

    let listener = match TcpListener::bind(addr).await {
        Ok(x) => x,
        Err(err) => {
            if config.bind_addr != Ipv6Addr::UNSPECIFIED {
                error!(
                    "Failed to bind the listener to {addr}; aborting startup:  {}",
                    ErrorReport(&err)
                );
                return Err(MainLoopError::Io(err));
            }

            // Fallback to IPv4 to avoid errors when IPv6 is not available and the default configuration is used.
            addr = SocketAddr::from((Ipv4Addr::UNSPECIFIED, config.bind_port.get()));
            TcpListener::bind(addr)
                .await
                .inspect_err(|err| {
                    error!(
                        "Failed to bind the IPv4 fallback listener to {addr}; aborting startup:  {}",
                        ErrorReport(err)
                    );
                })
                .map_err(MainLoopError::Io)?
        }
    };
    info!("Ready and listening on http://{addr}");

    let drain_db_task = async move {
        if db_shutdown_tx.send(true).is_err() {
            warn!(
                "Database task already exited before the shutdown signal was sent; continuing shutdown without draining it"
            );
        }
        match tokio::time::timeout(DB_DRAIN_TIMEOUT, db_join).await {
            Ok(Ok(())) => {}
            Ok(Err(err)) => error!(
                "Database task did not exit cleanly; buffered download/delivery/origin rows are lost:  {}",
                ErrorReport(&err)
            ),
            Err(_) => error!(
                "Database task did not drain within {}; abandoning it and losing the buffered download/delivery/origin rows",
                HumanFmt::Time(DB_DRAIN_TIMEOUT)
            ),
        }
    };
    tokio::pin!(drain_db_task);

    loop {
        trace!(
            "Active downloads ({}):  {:?}",
            appstate.active_downloads.len(),
            appstate.active_downloads
        );

        let next = tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                info!("SIGINT received, stopping...");
                log_shutdown_summary("SIGINT", &appstate.active_downloads);
                drain_db_task.as_mut().await;
                return Ok(());
            },
            _ = term_signal.recv() => {
                info!("SIGTERM received, stopping...");
                log_shutdown_summary("SIGTERM", &appstate.active_downloads);
                drain_db_task.as_mut().await;
                return Ok(());
            },
            _ = cleanup_interval.tick() => {
                info!("Daily cleanup issued...");
                set_next_cleanup_epoch(
                    time::OffsetDateTime::now_utc().unix_timestamp()
                        + i64::try_from(CLEANUP_INTERVAL_SECS).expect("CLEANUP_INTERVAL_SECS fits in i64"),
                );
                let appstate = appstate.clone();
                tokio::task::spawn(async move {
                    task_cleanup(&appstate).await;
                });
                continue;
            },
            _ = usr1_signal.recv() => {
                if let Some(output_log_file) = OUTPUT_LOG_FILE.get() {
                    info!("SIGUSR1 received, requesting reopen of log file `{}`...", output_log_file.path.display());
                    output_log_file.request_reopen();
                } else {
                    info!("Ignoring SIGUSR1 because logging is set to console");
                }
                continue;
            },
            _ = usr2_signal.recv() => {
                info!("SIGUSR2 received, issuing cleanup...");
                cleanup_interval.reset();
                set_next_cleanup_epoch(
                    time::OffsetDateTime::now_utc().unix_timestamp()
                        + i64::try_from(CLEANUP_INTERVAL_SECS).expect("CLEANUP_INTERVAL_SECS fits in i64"),
                );
                let appstate = appstate.clone();
                tokio::task::spawn(async move {
                    task_cleanup(&appstate).await;
                });
                continue;
            },
            n = listener.accept() => n
        };

        let (stream, client) = match next {
            Ok((stream, client)) => (stream, ClientInfo::new(client)),
            // Descriptor/buffer exhaustion and a peer that reset before
            // accept() are load conditions, not listener faults: an idle
            // connection flood must degrade service, never stop the daemon.
            // Back off briefly so a saturated loop does not spin.
            Err(err) if is_transient_accept_error(&err) => {
                metrics::ACCEPT_TRANSIENT_FAILURES.increment();
                warn_once_or_info!(
                    "Failed to accept a client connection; retrying after {}:  {}",
                    HumanFmt::Time(ACCEPT_RETRY_DELAY),
                    ErrorReport(&err)
                );
                tokio::time::sleep(ACCEPT_RETRY_DELAY).await;
                continue;
            }
            Err(err) => {
                error!(
                    "Failed to accept a client connection; stopping the daemon:  {}",
                    ErrorReport(&err)
                );
                return Err(MainLoopError::Io(err));
            }
        };

        metrics::CONNECTIONS_ACCEPTED.increment();

        let client_counter = match client_counter::ClientCounter::try_new(
            client.ip(),
            config.max_connections_per_client_ip,
            config.max_connections,
        ) {
            Ok(counter) => counter,
            Err(cap) => {
                // Per rejected connection, on exactly the path a flood exercises.
                match cap {
                    client_counter::ConnectionCap::PerIp(max) => warn_once_or_debug!(
                        "Rejecting connection from client {client}: \
                         `max_connections_per_client_ip` ({max}) reached, closing the socket without a response"
                    ),
                    client_counter::ConnectionCap::Global(max) => warn_once_or_debug!(
                        "Rejecting connection from client {client}: \
                         `max_connections` ({max}) reached, closing the socket without a response"
                    ),
                }
                // Drop the stream; closing the socket is the cheapest available
                // signal — sending a 503 would itself be subject to the same load.
                drop(stream);
                continue;
            }
        };

        debug!("New client connection from {client}");
        let client_start = Instant::now();

        let appstate = appstate.clone();
        tokio::task::spawn(async move {
            #[cfg(feature = "sendfile")]
            Box::pin(sendfile_conn::handle_sendfile_connection(
                stream, client, appstate,
            ))
            .await;

            #[cfg(not(feature = "sendfile"))]
            handle_hyper_connection(stream, client, appstate, None).await;

            debug!(
                "Closed connection to client {client} after {}",
                HumanFmt::Time(client_start.elapsed().into())
            );

            drop(client_counter);
        });
    }
}

/// Pause after a transient `accept(2)` failure before retrying.
const ACCEPT_RETRY_DELAY: Duration = Duration::from_millis(100);

/// Whether an `accept(2)` error is a passing load condition worth retrying
/// (descriptor or buffer exhaustion, a peer gone before accept) rather than
/// a broken listener.
fn is_transient_accept_error(err: &std::io::Error) -> bool {
    let Some(errno) = err.raw_os_error().map(nix::errno::Errno::from_raw) else {
        return false;
    };
    errno == nix::errno::Errno::EMFILE
        || errno == nix::errno::Errno::ENFILE
        || errno == nix::errno::Errno::ENOBUFS
        || errno == nix::errno::Errno::ENOMEM
        || errno == nix::errno::Errno::ECONNABORTED
}

#[cfg(test)]
mod accept_error_tests {
    use super::*;

    #[test]
    fn fd_and_buffer_exhaustion_are_transient() {
        for errno in [
            nix::errno::Errno::EMFILE,
            nix::errno::Errno::ENFILE,
            nix::errno::Errno::ENOBUFS,
            nix::errno::Errno::ENOMEM,
            nix::errno::Errno::ECONNABORTED,
        ] {
            let err = std::io::Error::from_raw_os_error(errno as i32);
            assert!(is_transient_accept_error(&err), "{errno}");
        }
    }

    #[test]
    fn other_accept_errors_are_fatal() {
        let err = std::io::Error::from_raw_os_error(nix::errno::Errno::EBADF as i32);
        assert!(!is_transient_accept_error(&err));
        assert!(!is_transient_accept_error(&std::io::Error::other("x")));
    }
}
