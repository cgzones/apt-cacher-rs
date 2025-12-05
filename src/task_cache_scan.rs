use std::{ffi::OsStr, path::Path};

use log::{error, trace, warn};
use tokio::fs::DirEntry;

use crate::{
    database::{Database, MirrorEntry},
    error::ProxyCacheError,
    global_config,
};

/// Returns the size in bytes of the entire cache.
/// Files that cannot be accessed are not included, but logged about.
pub(crate) async fn task_cache_scan(database: &Database) -> Result<u64, ProxyCacheError> {
    let mirrors = match database.get_mirrors().await {
        Ok(m) => m,
        Err(err) => {
            error!("Error fetching mirrors:  {err}");
            return Err(ProxyCacheError::Sqlx(err));
        }
    };

    let cache_path = &global_config().cache_directory;

    trace!("Scanning directory `{}`...", cache_path.display());

    let mut cache_dir = match tokio::fs::read_dir(cache_path).await {
        Ok(d) => d,
        Err(err) => {
            error!(
                "Error listing cache directory `{}`:  {err}",
                cache_path.display()
            );
            return Err(ProxyCacheError::Io(err));
        }
    };

    let aliases = global_config().aliases.as_slice();

    let mut cache_size = 0;

    while let Some(entry) = match cache_dir.next_entry().await {
        Ok(e) => e,
        Err(err) => {
            error!(
                "Error iterating cache directory `{}`:  {err}",
                cache_path.display()
            );
            return Err(ProxyCacheError::Io(err));
        }
    } {
        if let Ok(mdata) = entry.metadata().await
            && !mdata.is_dir()
        {
            cache_size += mdata.len();
        }

        let filename = entry.file_name();
        if filename == "tmp" {
            continue;
        }

        let mut scanned = false;

        for mirror in &mirrors {
            if let Some(port) = mirror.port() {
                if Path::new(&format!("{}:{port}", mirror.host)) != filename {
                    continue;
                }
            } else if Path::new(&mirror.host) != filename {
                continue;
            }

            if !scanned {
                if let Some(alias) = aliases
                    .iter()
                    .find(|alias| alias.aliases.binary_search(&mirror.host).is_ok())
                {
                    warn!(
                        "Entry for aliased host {} found (aliased to {})",
                        mirror.host, alias.main
                    );
                }
                scanned = true;
            }

            cache_size += scan_mirror_dir(&entry, mirror).await;
        }

        if !scanned {
            warn!(
                "Unrecognized entry in cache directory: `{}`",
                filename.to_string_lossy()
            );
        }
    }

    Ok(cache_size)
}

#[must_use]
async fn scan_mirror_dir(host: &DirEntry, mirror: &MirrorEntry) -> u64 {
    let mirror_dir = {
        let mut p = host.path();
        let mpath = Path::new(&mirror.path);
        assert!(mpath.is_relative());
        p.push(mpath);
        p
    };

    trace!("Scanning mirror directory `{}`...", mirror_dir.display());

    let mut host_dir = match tokio::fs::read_dir(&mirror_dir).await {
        Ok(d) => d,
        Err(err) => {
            error!(
                "Error listing mirror directory `{}`:  {err}",
                mirror_dir.display()
            );
            return 0;
        }
    };

    let mut dir_size = 0;

    while let Some(entry) = match host_dir.next_entry().await {
        Ok(e) => e,
        Err(err) => {
            error!(
                "Error iterating mirror directory `{}`:  {err}",
                mirror_dir.display()
            );
            return dir_size;
        }
    } {
        let file_path = entry.path();

        let mdata = match entry.metadata().await {
            Ok(d) => d,
            Err(err) => {
                error!(
                    "Error getting file meta data of `{}`:  {err}",
                    file_path.display()
                );
                continue;
            }
        };

        let file_type = mdata.file_type();

        if !file_type.is_dir() {
            dir_size += mdata.len();
        }

        if file_type.is_file() && file_path.extension() == Some(OsStr::new("deb")) {
            continue;
        }

        if file_type.is_dir() && entry.file_name() == "dists" {
            dir_size += scan_sub_dir(entry).await;
            continue;
        }

        warn!(
            "Unrecognized entry in host directory: `{}`",
            file_path.display()
        );
    }

    trace!(
        "Size of mirror directory `{}`: {}",
        mirror_dir.display(),
        dir_size
    );

    dir_size
}

#[must_use]
async fn scan_sub_dir(entry: DirEntry) -> u64 {
    let entry_path = entry.path();

    trace!(
        "Scanning mirror sub directory `{}`...",
        entry_path.display()
    );

    let mut dir = match tokio::fs::read_dir(&entry_path).await {
        Ok(d) => d,
        Err(err) => {
            error!(
                "Error listing mirror sub directory `{}`:  {err}",
                entry_path.display()
            );
            return 0;
        }
    };

    let mut dir_size = 0;

    while let Some(entry) = match dir.next_entry().await {
        Ok(e) => e,
        Err(err) => {
            error!(
                "Error iterating mirror sub directory `{}`:  {err}",
                entry_path.display()
            );
            return dir_size;
        }
    } {
        let file_path = entry.path();

        let mdata = match entry.metadata().await {
            Ok(d) => d,
            Err(err) => {
                error!(
                    "Error getting file meta data of `{}`:  {err}",
                    file_path.display()
                );
                continue;
            }
        };

        let file_type = mdata.file_type();

        if !file_type.is_dir() {
            dir_size += mdata.len();
        }

        if file_type.is_file() {
            continue;
        }

        if file_type.is_dir() && entry.file_name() == "by-hash" {
            dir_size += scan_sub2_dir(entry).await;
            continue;
        }

        warn!(
            "Unrecognized entry in mirror sub directory `{}`: `{}`",
            entry_path.display(),
            file_path.display()
        );
    }

    trace!(
        "Size of mirror sub directory `{}`: {}",
        entry_path.display(),
        dir_size
    );

    dir_size
}

#[must_use]
async fn scan_sub2_dir(entry: DirEntry) -> u64 {
    let entry_path = entry.path();

    trace!(
        "Scanning mirror sub^2 directory `{}`...",
        entry_path.display()
    );

    let mut dir = match tokio::fs::read_dir(&entry_path).await {
        Ok(d) => d,
        Err(err) => {
            error!(
                "Error listing mirror sub^2 directory `{}`:  {err}",
                entry_path.display()
            );
            return 0;
        }
    };

    let mut dir_size = 0;

    while let Some(entry) = match dir.next_entry().await {
        Ok(e) => e,
        Err(err) => {
            error!(
                "Error iterating mirror sub^2 directory `{}`:  {err}",
                entry_path.display()
            );
            return dir_size;
        }
    } {
        let file_path = entry.path();

        let mdata = match entry.metadata().await {
            Ok(d) => d,
            Err(err) => {
                error!(
                    "Error getting file meta data of `{}`:  {err}",
                    file_path.display()
                );
                continue;
            }
        };

        let file_type = mdata.file_type();

        if !file_type.is_dir() {
            dir_size += mdata.len();
        }

        if file_type.is_file() {
            continue;
        }

        warn!(
            "Unrecognized entry in mirror sub^2 directory `{}`: `{}`",
            entry_path.display(),
            file_path.display()
        );
    }

    trace!(
        "Size of mirror sub^2 directory `{}`: {}",
        entry_path.display(),
        dir_size
    );

    dir_size
}
