use std::{
    collections::HashMap,
    ffi::OsString,
    io::ErrorKind,
    path::{Path, PathBuf},
    sync::OnceLock,
    time::{Duration, Instant, SystemTime},
};

use http_body_util::{BodyExt, Empty};
use hyper::{Method, Request, Response, StatusCode, body::Incoming};
use log::{debug, error, info, trace, warn};
use memfd::MemfdOptions;
use tokio::io::{AsyncBufRead, AsyncBufReadExt, BufWriter};
use tokio::io::{AsyncSeekExt, AsyncWriteExt};

use crate::{
    ActiveDownloads, Client, ProxyCacheError, RETENTION_TIME, RUNTIMEDETAILS,
    config::DomainName,
    database::Database,
    deb_mirror::{Mirror, UriFormat},
    global_config,
    humanfmt::HumanFmt,
    info_once, request_with_retry, task_cache_scan,
};

async fn body_to_file(body: &mut Incoming, file: tokio::fs::File) -> Result<(), ProxyCacheError> {
    let mut writer = BufWriter::with_capacity(global_config().buffer_size, file);

    while let Some(next) = body.frame().await {
        let frame = next?;
        if let Ok(mut chunk) = frame.into_data() {
            writer.write_all_buf(&mut chunk).await?;
        }
    }

    writer.flush().await?;

    Ok(())
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

        if let Some(ext) = path.extension()
            && ext == "deb"
        {
            ret.insert(entry.file_name(), path);
        }
    }

    Ok(ret)
}

enum PackageFormat {
    Raw,
    Gz,
    Xz,
}

impl PackageFormat {
    #[must_use]
    const fn extension(&self) -> &'static str {
        match self {
            Self::Raw => "",
            Self::Gz => ".gz",
            Self::Xz => ".xz",
        }
    }

    // TODO: verify hashes
    async fn reduce_file_list(
        &self,
        mut file: tokio::fs::File,
        name: &str,
        file_list: &mut HashMap<OsString, PathBuf>,
    ) -> Result<(), ProxyCacheError> {
        debug_assert!(!file_list.is_empty());

        file.rewind().await.map_err(|err| {
            error!("Error rewinding in-memory file `{name}`:  {err}");
            err
        })?;

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

        while let Some(line) = reader.lines().next_line().await.map_err(|err| {
            error!("Error reading in-memory file `{name}`:  {err}");
            err
        })? {
            let Some(filepath) = line.strip_prefix("Filename: ") else {
                continue;
            };

            let Some(filename) = Path::new(filepath).file_name() else {
                continue;
            };

            if file_list.remove(filename).is_some() && file_list.is_empty() {
                break;
            }
        }

        Ok(())
    }
}

enum GetPackageError {
    Http(StatusCode),
    HyperUtil(hyper_util::client::legacy::Error),
}

async fn get_package_file(
    uri: &str,
    https_client: Client,
) -> Result<(Response<Incoming>, PackageFormat), GetPackageError> {
    for pkgfmt in [PackageFormat::Xz, PackageFormat::Gz, PackageFormat::Raw] {
        let uri_tmp = uri.to_string() + pkgfmt.extension();

        let mut tries = 0;
        let response = loop {
            const MAX_TRIES: u32 = 4;
            let req = Request::builder()
                .method(Method::GET)
                .uri(&uri_tmp)
                .body(Empty::new())
                .expect("Request should be valid");
            match request_with_retry(&https_client, req).await {
                Ok(r) => break r,
                Err(err) => {
                    // TODO: retry based on error kind
                    // TODO: add error kind to hyper_util::client::legacy::client::Error
                    debug!(
                        "Failed to retrieve {uri_tmp} ({}/{}):  {err}",
                        tries + 1,
                        MAX_TRIES
                    );
                    if tries >= MAX_TRIES {
                        error!("Failed to retrieve {uri_tmp} after {MAX_TRIES} retries:  {err}");
                        return Err(GetPackageError::HyperUtil(err));
                    }
                    tries += 1;
                    tokio::time::sleep(Duration::from_secs((tries * tries).into())).await;
                    continue;
                }
            }
        };

        if response.status() == StatusCode::NOT_FOUND {
            debug!("Request {uri_tmp} not found");
            continue;
        }

        if response.status() != StatusCode::OK {
            warn!(
                "Request {uri_tmp} failed with status code {}:  {response:?}",
                response.status(),
            );
            return Err(GetPackageError::Http(response.status()));
        }

        return Ok((response, pkgfmt));
    }

    Err(GetPackageError::Http(StatusCode::NOT_FOUND))
}

pub(crate) async fn task_cleanup(
    database: Database,
    https_client: Client,
    active_downloads: ActiveDownloads,
) -> Result<(), ProxyCacheError> {
    static TASK_ACTIVE: OnceLock<parking_lot::Mutex<bool>> = OnceLock::new();

    let mutex = TASK_ACTIVE.get_or_init(|| parking_lot::Mutex::new(false));

    {
        let mut val = mutex.lock();
        if *val {
            info!("Skipping cleanup task since already in progress");
            return Ok(());
        }
        *val = true;
    }

    let ret = task_cleanup_impl(database, https_client, active_downloads).await;

    {
        let mut val = mutex.lock();
        assert!(*val);
        *val = false;
    }

    ret
}

async fn task_cleanup_impl(
    database: Database,
    https_client: Client,
    active_downloads: ActiveDownloads,
) -> Result<(), ProxyCacheError> {
    let start = Instant::now();

    let usage_retention_days = global_config().usage_retention_days;
    if usage_retention_days != 0 {
        let keep_date =
            SystemTime::now() - Duration::from_secs(usage_retention_days * 24 * 60 * 60);
        match keep_date.duration_since(SystemTime::UNIX_EPOCH) {
            Ok(val) => {
                if let Err(err) = database.delete_usage_logs(val).await {
                    error!("Failed to delete old usage logs:  {err}");
                }
            }
            Err(err) => error!("Failed to compute date for usage data retention:  {err}"),
        }
    }

    let mirrors = database.get_mirrors().await.map_err(|err| {
        error!("Error looking up hosts:  {err}");
        err
    })?;

    trace!("Mirrors ({}): {mirrors:?}", mirrors.len());
    info!("Found {} mirrors for cleanup", mirrors.len());

    let mut tasks = Vec::with_capacity(mirrors.len());
    for mirror in mirrors {
        tasks.push(tokio::task::spawn(cleanup_mirror_deb_files(
            mirror.host.clone(),
            mirror.path.clone(),
            database.clone(),
            https_client.clone(),
        )));

        tasks.push(tokio::task::spawn(cleanup_mirror_byhash_files(
            mirror.host,
            mirror.path,
        )));
    }

    let mut files_retained = 0;
    let mut files_removed = 0;
    let mut bytes_removed = 0;

    for task in tasks {
        let task_result = match task.await {
            Ok(tr) => tr,
            Err(err) => {
                error!("Error joining task:  {err}");
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

        if let Err(err) = database.mirror_cleanup(&cleanup_result.mirror).await {
            error!("Error setting cleanup timestamp:  {err}");
        }

        files_retained += cleanup_result.files_retained;
        files_removed += cleanup_result.files_removed;
        bytes_removed += cleanup_result.bytes_removed;
    }

    if let Ok(actual_cache_size) = task_cache_scan(database).await {
        let active_downloading_size = active_downloads.download_size();

        let mut mg_cache_size = RUNTIMEDETAILS
            .get()
            .expect("global set in main")
            .cache_size
            .lock();

        match mg_cache_size.checked_sub(bytes_removed) {
            Some(val) => *mg_cache_size = val,
            None => {
                error!(
                    "Cache size corruption: current={}, removed={}",
                    *mg_cache_size, bytes_removed
                );
            }
        }

        let cache_size = *mg_cache_size;
        let difference = cache_size.abs_diff(actual_cache_size + active_downloading_size);

        // Auto-repair small abnormalities
        {
            const AUTO_REPAIR_THRESHOLD: u64 = 10 * 1024; // 10 KiB
            if difference != 0 && difference < AUTO_REPAIR_THRESHOLD {
                debug!(
                    "Auto-repairing small cache size difference of {difference} (cache_size={cache_size}, actual_cache_size={actual_cache_size}, active_downloading_size={active_downloading_size}, threshold={AUTO_REPAIR_THRESHOLD})"
                );
                *mg_cache_size = actual_cache_size + active_downloading_size;
            }
        }

        drop(mg_cache_size);

        if difference == 0 {
            debug!(
                "actual cache size: {actual_cache_size}; stored cache size: {cache_size}; active download size: {active_downloading_size}",
            );
        } else {
            // TODO: check for inconsistencies and repair

            warn!(
                "actual cache size: {actual_cache_size}; stored cache size: {cache_size}; active download size: {active_downloading_size}; size difference: {difference}",
            );
        }
    }

    info!(
        "Finished cleanup task in {}s: retained {} files, removed {} files of size {}",
        start.elapsed().as_secs(),
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
    host: DomainName,
    path: String,
    database: Database,
    https_client: Client,
) -> Result<CleanupDone, ProxyCacheError> {
    let origins = database
        .get_origins_by_mirror(&host, &path)
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

    let mirror_path: PathBuf = [
        &global_config().cache_directory,
        Path::new(&host),
        Path::new(&path),
    ]
    .iter()
    .collect();

    let mut cached_files = collect_cached_files(&mirror_path).await.map_err(|err| {
        error!("Error listing files in `{}`:  {err}", mirror_path.display());
        err
    })?;

    let num_total_files = cached_files.len() as u64;

    trace!("Cached files ({}): {cached_files:?}", cached_files.len());

    info!(
        "Found {} active origins and {} cached deb files for mirror {}/{}",
        active_origins.len(),
        cached_files.len(),
        host,
        path
    );

    if cached_files.is_empty() {
        return Ok(CleanupDone {
            mirror: Mirror { host, path },
            files_retained: num_total_files,
            files_removed: 0,
            bytes_removed: 0,
        });
    }

    for origin in &active_origins {
        let (mut response, pkgfmt) = match get_package_file(&origin.uri(), https_client.clone())
            .await
        {
            Ok(r) => r,
            Err(GetPackageError::Http(status)) if status == StatusCode::NOT_FOUND => {
                warn!(
                    "Could not find package file for {origin:?}; continuing cleanup for mirror {host}/{path}..."
                );
                continue;
            }
            Err(GetPackageError::Http(status)) => {
                warn!(
                    "Could not find package file for {origin:?} ({status}); skipping cleanup for mirror {host}/{path}"
                );

                return Ok(CleanupDone {
                    mirror: Mirror { host, path },
                    files_retained: num_total_files,
                    files_removed: 0,
                    bytes_removed: 0,
                });
            }
            Err(GetPackageError::HyperUtil(err)) => {
                error!("Failed to retrieve package file for {origin:?}:  {err}");
                return Err(ProxyCacheError::HyperUtil(err));
            }
        };

        let name = origin.distribution.clone()
            + "_"
            + &origin.component
            + "_"
            + &origin.architecture
            + "_"
            + "packages"
            + pkgfmt.extension();

        let memfd = MemfdOptions::new().create(&name).map_err(|err| {
            error!("Error creating in-memory file `{name}`:  {err}");
            ProxyCacheError::Memfd(err)
        })?;

        let file = tokio::fs::File::from_std(memfd.into_file());

        let file_copy = file.try_clone().await.map_err(|err| {
            error!("Error duplicating in-memory file `{name}`:  {err}");
            err
        })?;

        body_to_file(response.body_mut(), file_copy)
            .await
            .map_err(|err| {
                error!("Error writing response to in-memory file `{name}`:  {err}");
                err
            })?;

        pkgfmt
            .reduce_file_list(file, &name, &mut cached_files)
            .await?;

        if cached_files.is_empty() {
            return Ok(CleanupDone {
                mirror: Mirror { host, path },
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
            const KEEP_SPAN: Duration = Duration::from_secs(3 * 24 * 60 * 60); // 3 days

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
                    "Keeping unreferenced file `{}` since it is to new ({}s, threshold={}s)",
                    path.display(),
                    existing_for.as_secs(),
                    KEEP_SPAN.as_secs()
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
        "Removed {files_removed} unreferenced deb files for mirror {host}/{path} ({})",
        HumanFmt::Size(bytes_removed)
    );

    Ok(CleanupDone {
        mirror: Mirror { host, path },
        files_retained: num_total_files - files_removed,
        files_removed,
        bytes_removed,
    })
}

async fn cleanup_mirror_byhash_files(
    host: DomainName,
    path: String,
) -> Result<CleanupDone, ProxyCacheError> {
    let mut bytes_removed = 0;
    let mut files_removed = 0;
    let mut files_retained = 0;
    let now = SystemTime::now();
    let keep_span = Duration::from_secs(24 * 60 * 60 * global_config().byhash_retention_days);

    let mirror_byhash_path: PathBuf = [
        &global_config().cache_directory,
        Path::new(&host),
        Path::new(&path),
        Path::new("dists/by-hash"),
    ]
    .iter()
    .collect();

    let mut byhash_dir = match tokio::fs::read_dir(&mirror_byhash_path).await {
        Ok(d) => d,
        Err(err) if err.kind() == ErrorKind::NotFound => {
            debug!(
                "Directory {} not found. Cleanup skipped.",
                mirror_byhash_path.to_string_lossy()
            );
            return Ok(CleanupDone {
                mirror: Mirror { host, path },
                files_retained,
                files_removed,
                bytes_removed,
            });
        }
        Err(err) => {
            error!(
                "Error traversing directory {}: {}",
                mirror_byhash_path.to_string_lossy(),
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
                    "Failed to compute modification timespan for file `{}`: {err}",
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
            error!("Error removing file `{}`: {err}", path.display());
            continue;
        }

        bytes_removed += metadata.len();
        files_removed += 1;
        files_retained -= 1;
    }

    info!(
        "Removed {files_removed} files acquired by-hash for mirror {}/{} ({})",
        host,
        path,
        HumanFmt::Size(bytes_removed)
    );

    Ok(CleanupDone {
        mirror: Mirror { host, path },
        files_retained,
        files_removed,
        bytes_removed,
    })
}
