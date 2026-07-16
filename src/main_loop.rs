use std::{
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    time::Duration,
};

use coarsetime::Instant;
use futures_util::StreamExt as _;
use http::{Method, Request, Uri, header::USER_AGENT};
use http_body_util::Empty;
use tokio::{net::TcpListener, signal::unix::SignalKind};
use tracing::{debug, error, info, trace, warn};

#[cfg(not(feature = "sendfile"))]
use crate::hyper_conn::handle_hyper_connection;
#[cfg(feature = "sendfile")]
use crate::sendfile_conn;
use crate::{
    APP_USER_AGENT, AppState, ClientInfo, DB_DRAIN_TIMEOUT, OUTPUT_LOG_FILE, RUNTIMEDETAILS,
    SCHEME_CACHE,
    active_downloads::ActiveDownloads,
    cache_layout, cache_metadata,
    cleanup::{
        CLEANUP_INTERVAL_SECS, FIRST_CLEANUP_DELAY_SECS, set_next_cleanup_epoch, task_cleanup,
    },
    client_counter,
    database::Database,
    database_task::{self, db_loop},
    deb_mirror,
    error::ErrorReport,
    flat_blocklist, global_config,
    humanfmt::HumanFmt,
    hyper_conn::{HttpClient, request_with_retry},
    metrics,
    task_cache_scan::task_cache_scan,
};

pub(crate) async fn main_loop(
    https_client: HttpClient,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let config = global_config();

    let database = Database::connect(&config.database_path, config.database_slow_timeout)
        .await
        .inspect_err(|err| {
            error!(
                "Error creating database `{}`:  {err}",
                config.database_path.display()
            );
        })?;

    database.init_tables().await.inspect_err(|err| {
        error!(
            "Error initializing database `{}`:  {err}",
            config.database_path.display()
        );
    })?;

    database.cleanup_invalid_rows().await.inspect_err(|err| {
        error!("Failed to clean up invalid database rows:  {err}");
    })?;

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
    flat_blocklist::init(&database).await.inspect_err(|err| {
        error!("Failed to load flat-collision mirrors at startup:  {err}");
    })?;

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
    let mirrors = database.get_mirrors().await.inspect_err(|err| {
        error!("Failed to scan mirrors for reserved-segment migration warning:  {err}");
    })?;

    for mirror in &mirrors {
        if deb_mirror::mirror_path_has_reserved_segment(&mirror.path) {
            warn!(
                "Pre-existing mirror row `{}/{}` uses a reserved path segment (one of {:?}); cleanup walks may collide with cache plumbing - investigate and consider removing the row",
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
    for mirror in &mirrors {
        let legacy_flat = config
            .cache_directory
            .join(mirror.cache_host().format_cache_dir(mirror.port()).as_ref())
            .join(&mirror.path)
            .join(cache_layout::SUBDIR_FLAT);
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

    // Initial cache scan task
    {
        let database = database.clone();
        tokio::task::spawn(async move {
            match task_cache_scan(&database).await {
                Ok(cache_size) => {
                    let rd = RUNTIMEDETAILS.get().expect("global set in main()");

                    rd.cache_quota.add(cache_size);

                    match rd.config.disk_quota {
                        Some(val) => {
                            let val = val.get();
                            if cache_size > val {
                                warn!(
                                    "Startup cache size of {} exceeds quota {}",
                                    HumanFmt::Size(cache_size),
                                    HumanFmt::Size(val)
                                );
                            } else {
                                info!(
                                    "Startup cache size: {} (quota={})",
                                    HumanFmt::Size(cache_size),
                                    HumanFmt::Size(val)
                                );
                            }
                        }
                        None => {
                            info!(
                                "Startup cache size: {} (quota=unlimited)",
                                HumanFmt::Size(cache_size)
                            );
                        }
                    }
                }
                Err(err) => {
                    error!("Startup cache scan failed; cache size unset:  {err}");
                }
            }
        });
    }

    // Scheme cache initialization task

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
                    error!("Failed to get list of mirrors to initialize scheme cache:  {err}");
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
                                        "Initial scheme cache request to host {authority} returned server error {}",
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

            trace!(
                "Scheme cache:  {:?}",
                *SCHEME_CACHE.get().expect("initialized in main()").read()
            );

            debug!("Scheme cache initialization task finished");
        });
    }

    let mut term_signal = tokio::signal::unix::signal(SignalKind::terminate())?;
    let mut usr1_signal = tokio::signal::unix::signal(SignalKind::user_defined1())?;
    let mut usr2_signal = tokio::signal::unix::signal(SignalKind::user_defined2())?;

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
        https_client,
        active_downloads: ActiveDownloads::new(),
    };

    let mut addr = SocketAddr::from((config.bind_addr, config.bind_port.get()));

    let listener = match TcpListener::bind(addr).await {
        Ok(x) => x,
        Err(err) => {
            if config.bind_addr != Ipv6Addr::UNSPECIFIED {
                error!("Error binding on {addr}:  {}", ErrorReport(&err));
                return Err(err.into());
            }

            // Fallback to IPv4 to avoid errors when IPv6 is not available and the default configuration is used.
            addr = SocketAddr::from((Ipv4Addr::UNSPECIFIED, config.bind_port.get()));
            TcpListener::bind(addr).await.inspect_err(|err| {
                error!("Error binding fallback on {addr}:  {}", ErrorReport(err));
            })?
        }
    };
    info!("Ready and listening on http://{addr}");

    let drain_db_task = async move {
        if db_shutdown_tx.send(true).is_err() {
            warn!("Database task already exited before shutdown signal");
        }
        match tokio::time::timeout(DB_DRAIN_TIMEOUT, db_join).await {
            Ok(Ok(())) => {}
            Ok(Err(err)) => error!("Database task did not exit cleanly:  {err}"),
            Err(_) => error!(
                "Database task did not drain within {} seconds, abandoning",
                DB_DRAIN_TIMEOUT.as_secs()
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
                drain_db_task.as_mut().await;
                return Ok(());
            },
            _ = term_signal.recv() => {
                info!("SIGTERM received, stopping...");
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
                    if let Err(err) = task_cleanup(&appstate).await {
                        error!("Failed to perform daily cleanup task:  {err}");
                    }
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
                    if let Err(err) = task_cleanup(&appstate).await {
                        error!("Failed to perform SIGUSR2-triggered cleanup task:  {err}");
                    }
                });
                continue;
            },
            n = listener.accept() => n
        };

        let (stream, client) = next
            .map(|(stream, client)| (stream, ClientInfo::new(client)))
            .inspect_err(|err| {
                error!("Error accepting connection:  {}", ErrorReport(err));
            })?;

        metrics::CONNECTIONS_ACCEPTED.increment();

        let Some(client_counter) = client_counter::ClientCounter::try_new(
            client.ip(),
            config.max_connections_per_client_ip,
        ) else {
            info!(
                "Rejecting connection from client {client}: \
                 per-client-IP connection limit ({}) reached",
                config
                    .max_connections_per_client_ip
                    .expect("limit reached implies a configured cap")
            );
            // Drop the stream; closing the socket is the cheapest available
            // signal — sending a 503 would itself be subject to the same load.
            drop(stream);
            continue;
        };

        debug!("New client connection from {client}");
        let client_start = Instant::now();

        let appstate = appstate.clone();
        tokio::task::spawn(async move {
            #[cfg(feature = "sendfile")]
            sendfile_conn::handle_sendfile_connection(stream, client, appstate).await;

            #[cfg(not(feature = "sendfile"))]
            handle_hyper_connection(stream, client, appstate).await;

            debug!(
                "Closed connection to client {client} after {}",
                HumanFmt::Time(client_start.elapsed().into())
            );

            drop(client_counter);
        });
    }
}
