use std::{
    ffi::OsString,
    io::ErrorKind,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    path::{Path, PathBuf},
    sync::{
        LazyLock,
        atomic::{AtomicI64, Ordering},
    },
    time::{Duration, SystemTime},
};

use coarsetime::Instant;
use futures_util::StreamExt as _;
use hashbrown::HashMap;
use http_body_util::{BodyExt as _, Empty};
use hyper::{Method, Request, Response, StatusCode, header::CACHE_CONTROL};
use log::{debug, error, info, trace, warn};
use memfd::MemfdOptions;
use tokio::io::{AsyncBufRead, AsyncBufReadExt as _, BufWriter};
use tokio::io::{AsyncSeekExt as _, AsyncWriteExt as _};

use crate::{
    AppState, CachedFlavor, ClientInfo, ConnectionDetails, ProxyCacheBody, ProxyCacheError,
    RETENTION_TIME,
    database::{MirrorEntry, OriginEntry},
    deb_mirror::{Mirror, UriFormat as _, mirror_cache_path_impl},
    global_cache_quota, global_config,
    humanfmt::HumanFmt,
    info_once, metrics, process_cache_request, task_cache_scan,
};

/// Delay between daemon startup and the first scheduled cleanup run.
pub(crate) const FIRST_CLEANUP_DELAY_SECS: u64 = 60 * 60;

/// Interval between recurring cleanup runs.
pub(crate) const CLEANUP_INTERVAL_SECS: u64 = 24 * 60 * 60;

/// Unix-timestamp of the next scheduled cleanup. Updated by main.rs at startup,
/// after each scheduled tick, and after a SIGUSR2-triggered reset. A value of
/// `0` means "not yet initialized".
static NEXT_CLEANUP_EPOCH: AtomicI64 = AtomicI64::new(0);

pub(crate) fn set_next_cleanup_epoch(epoch: i64) {
    NEXT_CLEANUP_EPOCH.store(epoch, Ordering::Relaxed);
}

#[must_use]
pub(crate) fn next_cleanup_epoch() -> i64 {
    NEXT_CLEANUP_EPOCH.load(Ordering::Relaxed)
}

async fn body_to_file(
    body: &mut ProxyCacheBody,
    file: tokio::fs::File,
) -> Result<tokio::fs::File, ProxyCacheError> {
    let mut writer = BufWriter::with_capacity(global_config().buffer_size, file);

    while let Some(next) = body.frame().await {
        let frame = next.map_err(|err| *err)?;
        if let Ok(mut chunk) = frame.into_data() {
            writer.write_all_buf(&mut chunk).await?;
        }
    }

    writer.flush().await?;

    let mut file = writer.into_inner();

    file.rewind().await?;

    Ok(file)
}

async fn collect_cached_files(
    host_path: &Path,
) -> Result<HashMap<OsString, PathBuf>, ProxyCacheError> {
    let mut ret = HashMap::new();

    let mut host_dir = match tokio::fs::read_dir(host_path).await {
        Ok(d) => d,
        Err(err) if err.kind() == ErrorKind::NotFound => return Ok(ret),
        Err(err) => return Err(ProxyCacheError::Io(err)),
    };

    while let Some(entry) = host_dir.next_entry().await? {
        let path = entry.path();

        if path.extension().is_some_and(|ext| ext == "deb") {
            ret.insert(entry.file_name(), path);
        }
    }

    Ok(ret)
}

#[derive(Clone, Copy)]
enum PackageFormat {
    Raw,
    Gz,
    Xz,
}

impl PackageFormat {
    #[must_use]
    const fn extension(self) -> &'static str {
        match self {
            Self::Raw => "",
            Self::Gz => ".gz",
            Self::Xz => ".xz",
        }
    }

    // TODO: verify hashes
    async fn reduce_file_list(
        self,
        file: tokio::fs::File,
        filename: &str,
        file_list: &mut HashMap<OsString, PathBuf>,
    ) -> Result<(), ProxyCacheError> {
        debug_assert!(!file_list.is_empty(), "avoid unnecessary work");

        let buffer_size = global_config().buffer_size;

        let mut file_reader = tokio::io::BufReader::with_capacity(buffer_size, file);

        let reader: &mut (dyn AsyncBufRead + Unpin + Send) = match self {
            Self::Raw => &mut file_reader,
            Self::Gz => {
                let decoder = async_compression::tokio::bufread::GzipDecoder::new(file_reader);

                &mut tokio::io::BufReader::with_capacity(buffer_size, decoder)
            }
            Self::Xz => {
                let decoder = async_compression::tokio::bufread::XzDecoder::new(file_reader);

                &mut tokio::io::BufReader::with_capacity(buffer_size, decoder)
            }
        };

        let mut buffer = String::with_capacity(128);
        loop {
            buffer.clear();
            match reader.read_line(&mut buffer).await {
                Ok(0) => return Ok(()), // EOF
                Err(err) => {
                    error!("Failed to read in-memory file `{filename}`:  {err}");
                    return Err(err.into());
                }
                Ok(_bytes_read) => {
                    let Some(filepath) = buffer.strip_prefix("Filename: ") else {
                        continue;
                    };

                    let Some(filename) = Path::new(filepath).file_name() else {
                        continue;
                    };

                    if file_list.remove(filename).is_some() && file_list.is_empty() {
                        // No files left to potentially remove
                        return Ok(());
                    }
                }
            }
        }
    }
}

async fn get_package_file(
    mirror: &Mirror,
    origin: &OriginEntry,
    appstate: &AppState,
) -> Result<(Response<ProxyCacheBody>, PackageFormat), StatusCode> {
    let base_uri = origin.uri();
    let distribution = &origin.distribution;
    let component = &origin.component;
    let architecture = &origin.architecture;

    let mut uri_buffer = String::with_capacity(base_uri.len() + 3);

    for pkgfmt in [PackageFormat::Xz, PackageFormat::Gz, PackageFormat::Raw] {
        uri_buffer.clear();
        uri_buffer.push_str(&base_uri);
        uri_buffer.push_str(pkgfmt.extension());
        let uri = uri_buffer.as_str();

        let req = Request::builder()
            .method(Method::GET)
            .uri(uri)
            .header(CACHE_CONTROL, "max-age=604800") // 1 week
            .body(Empty::new())
            .expect("Request should be valid");

        let conn_details = ConnectionDetails {
            client: ClientInfo::new(SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::new(127, 0, 0, 2),
                0,
            ))),
            mirror: mirror.clone(),
            aliased_host: None,
            debname: format!(
                "{distribution}_{component}_{architecture}_Packages{}",
                pkgfmt.extension()
            ),
            cached_flavor: CachedFlavor::Volatile,
            subdir: Some(Path::new("dists")),
        };

        let response = process_cache_request(conn_details, req, appstate.clone()).await;

        if response.status() == StatusCode::NOT_FOUND {
            debug!("Cleanup request {uri} not found");
            continue;
        }

        if response.status() != StatusCode::OK {
            warn!(
                "Cleanup request {uri} failed with status code {}:  {response:?}",
                response.status(),
            );
            return Err(response.status());
        }

        return Ok((response, pkgfmt));
    }

    Err(StatusCode::NOT_FOUND)
}

pub(crate) async fn task_cleanup(appstate: &AppState) -> Result<(), ProxyCacheError> {
    static TASK_ACTIVE: LazyLock<parking_lot::Mutex<bool>> =
        LazyLock::new(|| parking_lot::Mutex::new(false));

    let mutex = &*TASK_ACTIVE;

    {
        let mut val = mutex.lock();
        if *val {
            info!("Skipping cleanup task since already in progress");
            return Ok(());
        }
        *val = true;
    }

    let ret = task_cleanup_impl(appstate).await;

    {
        let mut val = mutex.lock();
        assert!(*val, "cleanup state must be active after completion");
        *val = false;
    }

    ret
}

async fn task_cleanup_impl(appstate: &AppState) -> Result<(), ProxyCacheError> {
    // Use buffer_unordered to limit concurrent cleanup tasks and avoid thundering herd
    const MAX_CONCURRENT_CLEANUP_TASKS: usize = 10;

    let start = Instant::now();

    if let Err(err) = appstate.database.cleanup_invalid_rows().await {
        error!("Failed to clean up invalid database rows:  {err}");
    }

    let usage_retention_days = global_config().usage_retention_days;
    if usage_retention_days != 0 {
        let retention_secs = usage_retention_days
            .checked_mul(24 * 60 * 60)
            .expect("overflow check during config parsing");
        let now_secs = coarsetime::Clock::now_since_epoch().as_secs();
        let keep_date = Duration::from_secs(now_secs.saturating_sub(retention_secs));
        if let Err(err) = appstate.database.delete_usage_logs(keep_date).await {
            error!("Failed to delete old usage logs:  {err}");
        }
    }

    let mirrors = appstate.database.get_mirrors().await.inspect_err(|err| {
        error!("Error looking up hosts:  {err}");
    })?;

    trace!("Mirrors ({}): {mirrors:?}", mirrors.len());
    info!("Found {} mirrors for cleanup", mirrors.len());

    cleanup_stale_partials(&global_config().cache_directory, &mirrors).await;

    // Create a stream of futures for both deb files and byhash files cleanup
    let cleanup_tasks = mirrors.into_iter().flat_map(|mirror| {
        [
            tokio::task::spawn(cleanup_mirror_deb_files(mirror.clone(), appstate.clone())),
            tokio::task::spawn(cleanup_mirror_byhash_files(mirror)),
        ]
    });

    let results = futures_util::stream::iter(cleanup_tasks)
        .buffer_unordered(MAX_CONCURRENT_CLEANUP_TASKS)
        .collect::<Vec<_>>()
        .await;

    let mut files_retained = 0;
    let mut files_removed = 0;
    let mut bytes_removed = 0;

    for res in results {
        let task_result = match res {
            Ok(tr) => tr,
            Err(err) => {
                error!("Error joining cleanup task:  {err}");
                continue;
            }
        };

        let cleanup_result = match task_result {
            Ok(cr) => cr,
            Err(err) => {
                error!("Error in cleanup task:  {err}");
                continue;
            }
        };

        if let Err(err) = appstate
            .database
            .mirror_cleanup(&cleanup_result.mirror)
            .await
        {
            error!("Error setting cleanup timestamp:  {err}");
        }

        files_retained += cleanup_result.files_retained;
        files_removed += cleanup_result.files_removed;
        bytes_removed += cleanup_result.bytes_removed;
    }

    if let Ok(actual_cache_size) = task_cache_scan(&appstate.database).await {
        let active_downloading_size = appstate.active_downloads.download_size();

        let quota = global_cache_quota();
        let (csize, difference) =
            quota.subtract_and_reconcile(bytes_removed, actual_cache_size, active_downloading_size);

        if difference != 0 {
            warn!(
                "Repaired cache size discrepancy of {difference}: actual={actual_cache_size} stored={csize} active={active_downloading_size}"
            );
        } else {
            debug!(
                "actual cache size: {actual_cache_size}; stored cache size: {csize}; active download size: {active_downloading_size}"
            );
        }
    }

    let elapsed = start.elapsed();
    metrics::CLEANUP_EVICTIONS.increment_by(files_removed);
    metrics::CLEANUP_BYTES_RECLAIMED.increment_by(bytes_removed);
    metrics::LAST_CLEANUP_DURATION_SECS.set(elapsed.as_secs());
    metrics::LAST_CLEANUP_FILES_REMOVED.set(files_removed);
    metrics::LAST_CLEANUP_BYTES_RECLAIMED.set(bytes_removed);

    info!(
        "Finished cleanup task in {}: retained {} files, removed {} files of size {}",
        HumanFmt::Time(elapsed.into()),
        files_retained,
        files_removed,
        HumanFmt::Size(bytes_removed)
    );

    Ok(())
}

struct CleanupDone {
    mirror: Mirror,
    files_retained: u64,
    files_removed: u64,
    bytes_removed: u64,
}

async fn cleanup_mirror_deb_files(
    mirror: MirrorEntry,
    appstate: AppState,
) -> Result<CleanupDone, ProxyCacheError> {
    let origins = appstate
        .database
        .get_origins_by_mirror(&mirror.host, mirror.port(), &mirror.path)
        .await
        .inspect_err(|err| {
            error!("Error looking up origins:  {err}");
        })?;

    trace!("Origins ({}): {origins:?}", origins.len());

    let now: Duration = coarsetime::Clock::now_since_epoch().into();

    trace!("Now: {now:?}");

    let active_origins = origins
        .into_iter()
        .filter(|origin| {
            Duration::from_secs(
                u64::try_from(origin.last_seen)
                    .expect("Database should never store negative timestamp"),
            ) + RETENTION_TIME
                > now
        })
        .collect::<Vec<_>>();

    let mirror_path: PathBuf = [&global_config().cache_directory, &mirror.cache_path()]
        .iter()
        .collect();

    let mut cached_files = collect_cached_files(&mirror_path)
        .await
        .inspect_err(|err| {
            error!("Error listing files in `{}`:  {err}", mirror_path.display());
        })?;

    let num_total_files = cached_files.len() as u64;

    trace!("Cached files ({}): {cached_files:?}", cached_files.len());

    info!(
        "Found {} active origins and {} cached deb files for mirror {}",
        active_origins.len(),
        cached_files.len(),
        mirror.cache_path().display(),
    );

    let mirror = Mirror {
        port: mirror.port(),
        host: mirror.host,
        path: mirror.path,
    };

    if cached_files.is_empty() {
        return Ok(CleanupDone {
            mirror,
            files_retained: num_total_files,
            files_removed: 0,
            bytes_removed: 0,
        });
    }

    for origin in &active_origins {
        let (mut response, pkgfmt) = match get_package_file(&mirror, origin, &appstate).await {
            Ok(r) => r,
            Err(StatusCode::NOT_FOUND) => {
                warn!(
                    "Could not find package file for {origin:?}; continuing cleanup for mirror {mirror}..."
                );
                continue;
            }
            Err(status) => {
                warn!(
                    "Could not find package file for {origin:?} ({status}); skipping cleanup for mirror {mirror}"
                );

                return Ok(CleanupDone {
                    mirror,
                    files_retained: num_total_files,
                    files_removed: 0,
                    bytes_removed: 0,
                });
            }
        };

        let memfdname = {
            let total_len = origin.distribution.len()
                + origin.component.len()
                + origin.architecture.len()
                + pkgfmt.extension().len()
                + 3
                + "packages".len();
            let mut buffer = String::with_capacity(total_len);

            buffer.push_str(&origin.distribution);
            buffer.push('_');
            buffer.push_str(&origin.component);
            buffer.push('_');
            buffer.push_str(&origin.architecture);
            buffer.push('_');
            buffer.push_str("packages");
            buffer.push_str(pkgfmt.extension());

            debug_assert_eq!(buffer.len(), total_len, "should pre-allocate correctly");

            buffer
        };

        let memfd = MemfdOptions::new().create(&memfdname).map_err(|err| {
            error!("Error creating in-memory file `{memfdname}`:  {err}");
            ProxyCacheError::Memfd(err)
        })?;

        let file = tokio::fs::File::from_std(memfd.into_file());

        let file = body_to_file(response.body_mut(), file)
            .await
            .inspect_err(|err| {
                error!("Failed to write response to in-memory file `{memfdname}`:  {err}");
            })?;

        pkgfmt
            .reduce_file_list(file, &memfdname, &mut cached_files)
            .await?;

        if cached_files.is_empty() {
            return Ok(CleanupDone {
                mirror,
                files_retained: num_total_files,
                files_removed: 0,
                bytes_removed: 0,
            });
        }
    }

    let mut bytes_removed = 0;
    let mut files_removed = 0;
    let now = SystemTime::now();

    for path in cached_files.values() {
        let data = match tokio::fs::metadata(path).await {
            Ok(d) => Some(d),
            Err(err) => {
                error!(
                    "Error inspecting unreferenced file `{}`:  {err}",
                    path.display()
                );
                None
            }
        };

        /*
         * File might be from an origin not yet registered.
         * For example if `apt update` was run un-proxied.
         */
        if let Some(data) = &data {
            const KEEP_SPAN: Duration = Duration::from_hours(3 * 24); // 3 days

            let created = match data.created() {
                Ok(d) => d,
                Err(created_err) => {
                    info_once!(
                        "Failed to get create timestamp for file `{}`:  {created_err}",
                        path.display()
                    );
                    match data.modified() {
                        Ok(d) => d,
                        Err(modified_err) => {
                            error!(
                                "Failed to get create and modify timestamp of file `{}`:  {created_err}  //  {modified_err}",
                                path.display()
                            );
                            continue;
                        }
                    }
                }
            };

            if let Ok(existing_for) = now.duration_since(created)
                && existing_for < KEEP_SPAN
            {
                debug!(
                    "Keeping unreferenced file `{}` since it is too new ({}, threshold={})",
                    path.display(),
                    HumanFmt::Time(existing_for),
                    HumanFmt::Time(KEEP_SPAN)
                );
                continue;
            }
        }

        let size = match &data {
            Some(d) => d.len(),
            None => 0,
        };

        if let Err(err) = tokio::fs::remove_file(&path).await {
            error!(
                "Error removing unreferenced file `{}`:  {err}",
                path.display()
            );
            continue;
        }

        debug!("Removed unreferenced file `{}`", path.display());

        bytes_removed += size;
        files_removed += 1;
    }

    info!(
        "Removed {files_removed} unreferenced deb files for mirror {mirror} ({})",
        HumanFmt::Size(bytes_removed)
    );

    Ok(CleanupDone {
        mirror,
        files_retained: num_total_files - files_removed,
        files_removed,
        bytes_removed,
    })
}

async fn cleanup_mirror_byhash_files(mirror: MirrorEntry) -> Result<CleanupDone, ProxyCacheError> {
    let mut bytes_removed = 0;
    let mut files_removed = 0;
    let mut files_retained = 0;
    let now = SystemTime::now();
    let keep_span = Duration::from_secs(24 * 60 * 60 * global_config().byhash_retention_days);

    let mirror_byhash_path: PathBuf = [
        &global_config().cache_directory,
        &mirror.cache_path(),
        Path::new("dists/by-hash"),
    ]
    .iter()
    .collect();

    let mirror = Mirror {
        port: mirror.port(),
        host: mirror.host,
        path: mirror.path,
    };

    let mut byhash_dir = match tokio::fs::read_dir(&mirror_byhash_path).await {
        Ok(d) => d,
        Err(err) if err.kind() == ErrorKind::NotFound => {
            debug!(
                "Directory `{}` not found. Cleanup skipped.",
                mirror_byhash_path.display()
            );
            return Ok(CleanupDone {
                mirror,
                files_retained,
                files_removed,
                bytes_removed,
            });
        }
        Err(err) => {
            error!(
                "Error traversing directory `{}`:  {}",
                mirror_byhash_path.display(),
                err
            );
            return Err(ProxyCacheError::Io(err));
        }
    };

    while let Some(entry) = byhash_dir.next_entry().await? {
        let path = entry.path();

        if path.file_name().is_none() {
            continue;
        }

        files_retained += 1;

        let metadata = match entry.metadata().await {
            Ok(d) => d,
            Err(err) => {
                error!("Error inspecting file `{}`:  {err}", path.display());
                return Err(ProxyCacheError::Io(err));
            }
        };

        let modified = match metadata.modified() {
            Ok(m) => m,
            Err(err) => {
                error!("Failed to get mtime of file `{}`:  {err}", path.display());
                return Err(ProxyCacheError::Io(err));
            }
        };

        let file_age = match now.duration_since(modified) {
            Ok(x) => x,
            Err(err) => {
                warn!(
                    "Failed to compute modification timespan for file `{}`:  {err}",
                    path.display()
                );
                continue;
            }
        };

        if file_age <= keep_span {
            debug!(
                "Keeping file `{}` since it is too new ({}s, threshold={}s)",
                path.display(),
                file_age.as_secs(),
                keep_span.as_secs()
            );
            continue;
        }

        debug!(
            "Removing file `{}` since it is too old ({}s, threshold={}s)",
            path.display(),
            file_age.as_secs(),
            keep_span.as_secs()
        );

        if let Err(err) = tokio::fs::remove_file(&path).await {
            error!("Error removing file `{}`:  {err}", path.display());
            continue;
        }

        bytes_removed += metadata.len();
        files_removed += 1;
        files_retained -= 1;
    }

    info!(
        "Removed {files_removed} files acquired by-hash for mirror {mirror} ({})",
        HumanFmt::Size(bytes_removed)
    );

    Ok(CleanupDone {
        mirror,
        files_retained,
        files_removed,
        bytes_removed,
    })
}

/// Remove stale `.partial` files that are older than 3 days.
///
/// Partial files live under `{cache_dir}/{mirror_dir}/tmp/*.partial`.
/// Iterates known mirror directories directly instead of walking the entire cache tree.
async fn cleanup_stale_partials(cache_dir: &Path, mirrors: &[MirrorEntry]) {
    const MAX_AGE: Duration = Duration::from_hours(3 * 24);

    let cutoff = SystemTime::now() - MAX_AGE;
    let mut removed = 0u64;

    for mirror in mirrors {
        let mirror_dir = mirror_cache_path_impl(&mirror.host, mirror.port(), &mirror.path);
        let tmp_dir: PathBuf = [cache_dir, mirror_dir.as_path(), Path::new("tmp")]
            .iter()
            .collect();
        removed += cleanup_partials_in_dir(&tmp_dir, &cutoff).await;
    }

    if removed > 0 {
        info!("Removed {removed} stale partial file(s)");
    }
}

/// Remove stale `.partial` files from a single `tmp/` directory.
async fn cleanup_partials_in_dir(tmp_dir: &Path, cutoff: &SystemTime) -> u64 {
    let mut entries = match tokio::fs::read_dir(tmp_dir).await {
        Ok(e) => e,
        Err(err) if err.kind() == ErrorKind::NotFound => {
            return 0;
        }
        Err(err) => {
            error!(
                "Failed to read partial directory `{}`:  {err}",
                tmp_dir.display()
            );
            return 0;
        }
    };

    let mut removed = 0u64;

    loop {
        let entry = match entries.next_entry().await {
            Ok(Some(e)) => e,
            Ok(None) => break,
            Err(err) => {
                error!(
                    "Failed to iterate partial directory `{}`:  {err}",
                    tmp_dir.display()
                );
                break;
            }
        };

        let name = entry.file_name();
        let Some(name_str) = name.to_str() else {
            error!("Failed to decode name of partial file `{}`", name.display());
            continue;
        };
        if !name_str.ends_with(".partial") {
            info!("Skipping non-partial file `{name_str}`");
            continue;
        }

        let md = match entry.metadata().await {
            Ok(m) => m,
            Err(err) => {
                error!("Failed to stat partial file `{name_str}`:  {err}");
                continue;
            }
        };

        // Delete zero-byte partials unconditionally (no useful data to resume from)
        // and non-zero partials that are older than the cutoff.
        let mtime = md.modified().unwrap_or(SystemTime::UNIX_EPOCH);
        if md.len() == 0 || mtime < *cutoff {
            let path = entry.path();
            if let Err(err) = tokio::fs::remove_file(&path).await {
                error!(
                    "Failed to remove stale partial file `{}`:  {err}",
                    path.display()
                );
            } else {
                debug!("Removed stale partial file `{}`", path.display());
                removed += 1;
            }
        }
    }

    removed
}
