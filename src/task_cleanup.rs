use std::{
    ffi::OsString,
    io::ErrorKind,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    path::{Path, PathBuf},
    sync::LazyLock,
    time::{Duration, SystemTime},
};

use coarsetime::Instant;
use hashbrown::HashMap;
use http_body_util::{BodyExt as _, Empty};
use hyper::{Method, Request, Response, StatusCode, header::CACHE_CONTROL};
use log::{debug, error, info, trace, warn};
use memfd::MemfdOptions;
use tokio::io::{AsyncSeekExt as _, AsyncWriteExt as _};
use tokio::{
    io::{AsyncBufRead, AsyncBufReadExt as _, BufWriter},
    task::JoinSet,
};

use crate::{
    AppState, CachedFlavor, ConnectionDetails, ProxyCacheBody, ProxyCacheError, RETENTION_TIME,
    RUNTIMEDETAILS,
    database::{MirrorEntry, OriginEntry},
    deb_mirror::{Mirror, UriFormat as _},
    global_config,
    humanfmt::HumanFmt,
    info_once, process_cache_request, task_cache_scan,
};

async fn body_to_file(
    body: &mut ProxyCacheBody,
    file: tokio::fs::File,
) -> Result<tokio::fs::File, ProxyCacheError> {
    let mut writer = BufWriter::with_capacity(global_config().buffer_size, file);

    while let Some(next) = body.frame().await {
        let frame = next?;
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
        debug_assert!(!file_list.is_empty());

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
                    error!("Error reading in-memory file `{filename}`:  {err}");
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
            client: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)),
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
        assert!(*val);
        *val = false;
    }

    ret
}

async fn task_cleanup_impl(appstate: &AppState) -> Result<(), ProxyCacheError> {
    let start = Instant::now();

    let usage_retention_days = global_config().usage_retention_days;
    if usage_retention_days != 0 {
        let keep_date =
            SystemTime::now() - Duration::from_secs(usage_retention_days * 24 * 60 * 60);
        match keep_date.duration_since(SystemTime::UNIX_EPOCH) {
            Ok(val) => {
                if let Err(err) = appstate.database.delete_usage_logs(val).await {
                    error!("Failed to delete old usage logs:  {err}");
                }
            }
            Err(err) => error!("Failed to compute date for usage data retention:  {err}"),
        }
    }

    let mirrors = appstate.database.get_mirrors().await.map_err(|err| {
        error!("Error looking up hosts:  {err}");
        err
    })?;

    trace!("Mirrors ({}): {mirrors:?}", mirrors.len());
    info!("Found {} mirrors for cleanup", mirrors.len());

    let mut set = JoinSet::new();

    for mirror in mirrors {
        set.spawn(cleanup_mirror_deb_files(mirror.clone(), appstate.clone()));

        set.spawn(cleanup_mirror_byhash_files(mirror));
    }

    let mut files_retained = 0;
    let mut files_removed = 0;
    let mut bytes_removed = 0;

    while let Some(res) = set.join_next().await {
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

        let mut mg_cache_size = RUNTIMEDETAILS
            .get()
            .expect("global set in main")
            .cache_size
            .lock();
        let mut csize = *mg_cache_size;

        match csize.checked_sub(bytes_removed) {
            Some(val) => csize = val,
            None => {
                error!("Cache size corruption: current={csize}, removed={bytes_removed}");
            }
        }

        let difference = csize.abs_diff(actual_cache_size + active_downloading_size);

        // Auto-repair small abnormalities
        {
            const AUTO_REPAIR_THRESHOLD: u64 = 10 * 1024; // 10 KiB
            if difference != 0 {
                if difference < AUTO_REPAIR_THRESHOLD {
                    csize = actual_cache_size + active_downloading_size;
                    debug!(
                        "Auto-repaired small cache size difference of {difference} (cache_size={csize}, actual_cache_size={actual_cache_size}, active_downloading_size={active_downloading_size}, threshold={AUTO_REPAIR_THRESHOLD})"
                    );
                } else {
                    warn!(
                        "actual cache size: {actual_cache_size}; stored cache size: {csize}; active download size: {active_downloading_size}; size difference: {difference}"
                    );
                }
            } else {
                debug!(
                    "actual cache size: {actual_cache_size}; stored cache size: {csize}; active download size: {active_downloading_size}"
                );
            }
        }

        *mg_cache_size = csize;
    }

    info!(
        "Finished cleanup task in {}: retained {} files, removed {} files of size {}",
        HumanFmt::Time(start.elapsed().into()),
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
        .map_err(|err| {
            error!("Error looking up origins:  {err}");
            err
        })?;

    trace!("Origins ({}): {origins:?}", origins.len());

    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_err(|err| {
            error!("Error getting current timestamp:  {err}");
            err
        })?;

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

    let mut cached_files = collect_cached_files(&mirror_path).await.map_err(|err| {
        error!("Error listing files in `{}`:  {err}", mirror_path.display());
        err
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

            debug_assert_eq!(buffer.len(), total_len);

            buffer
        };

        let memfd = MemfdOptions::new().create(&memfdname).map_err(|err| {
            error!("Error creating in-memory file `{memfdname}`:  {err}");
            ProxyCacheError::Memfd(err)
        })?;

        let file = tokio::fs::File::from_std(memfd.into_file());

        let file = body_to_file(response.body_mut(), file)
            .await
            .map_err(|err| {
                error!("Error writing response to in-memory file `{memfdname}`:  {err}");
                err
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
                    "Keeping unreferenced file `{}` since it is to new ({}, threshold={})",
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
                "Keeping file `{}` since it is to new ({}s, threshold={}s)",
                path.display(),
                file_age.as_secs(),
                keep_span.as_secs()
            );
            continue;
        }

        debug!(
            "Removing file `{}` since it is to old ({}s, threshold={}s)",
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
