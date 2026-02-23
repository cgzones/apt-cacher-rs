use std::{
    borrow::Cow,
    path::{Path, PathBuf},
};

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

    // Pre-compute formatted directory names for each mirror to avoid repeated allocations
    let mirrors_with_names: Vec<_> = mirrors
        .iter()
        .map(|mirror| {
            let dir_name: Cow<'_, Path> = if let Some(port) = mirror.port() {
                Cow::Owned(PathBuf::from(format!("{}:{port}", mirror.host)))
            } else {
                Cow::Borrowed(Path::new(&mirror.host))
            };
            (mirror, dir_name)
        })
        .collect();

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

        for (mirror, dir_name) in &mirrors_with_names {
            if filename != *dir_name {
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
    let mirror_path = {
        let mut p = host.path();
        let mpath = Path::new(&mirror.path);
        assert!(mpath.is_relative());
        p.push(mpath);
        p
    };

    trace!("Scanning mirror directory `{}`...", mirror_path.display());

    let mut mirror_dir = match tokio::fs::read_dir(&mirror_path).await {
        Ok(d) => d,
        Err(err) => {
            error!(
                "Error listing mirror directory `{}`:  {err}",
                mirror_path.display()
            );
            return 0;
        }
    };

    let mut dir_size = 0;

    while let Some(entry) = match mirror_dir.next_entry().await {
        Ok(e) => e,
        Err(err) => {
            error!(
                "Error iterating mirror directory `{}`:  {err}",
                mirror_path.display()
            );
            return dir_size;
        }
    } {
        let mdata = match entry.metadata().await {
            Ok(d) => d,
            Err(err) => {
                error!(
                    "Error getting file meta data of `{}`:  {err}",
                    entry.path().display()
                );
                continue;
            }
        };

        let file_type = mdata.file_type();

        if file_type.is_file() {
            dir_size += mdata.len();

            #[expect(clippy::case_sensitive_file_extension_comparisons)]
            if entry
                .file_name()
                .to_str()
                .is_some_and(|fname| fname.ends_with(".deb"))
            {
                continue;
            }
        }

        if file_type.is_dir() && entry.file_name() == "dists" {
            dir_size += scan_sub_dir(entry).await;
            continue;
        }

        warn!(
            "Unrecognized entry in host directory: `{}`",
            entry.path().display()
        );
    }

    trace!(
        "Size of mirror directory `{}`: {}",
        mirror_path.display(),
        dir_size
    );

    dir_size
}

#[must_use]
async fn scan_sub_dir(entry: DirEntry) -> u64 {
    let subdir_path = entry.path();

    trace!(
        "Scanning mirror sub directory `{}`...",
        subdir_path.display()
    );

    let mut subdir_dir = match tokio::fs::read_dir(&subdir_path).await {
        Ok(d) => d,
        Err(err) => {
            error!(
                "Error listing mirror sub directory `{}`:  {err}",
                subdir_path.display()
            );
            return 0;
        }
    };

    let mut dir_size = 0;

    while let Some(entry) = match subdir_dir.next_entry().await {
        Ok(e) => e,
        Err(err) => {
            error!(
                "Error iterating mirror sub directory `{}`:  {err}",
                subdir_path.display()
            );
            return dir_size;
        }
    } {
        let mdata = match entry.metadata().await {
            Ok(d) => d,
            Err(err) => {
                error!(
                    "Error getting file meta data of `{}`:  {err}",
                    entry.path().display()
                );
                continue;
            }
        };

        let file_type = mdata.file_type();

        if file_type.is_file() {
            dir_size += mdata.len();
            continue;
        }

        if file_type.is_dir() && entry.file_name() == "by-hash" {
            dir_size += scan_by_hash_dir(entry).await;
            continue;
        }

        warn!(
            "Unrecognized entry in mirror sub directory `{}`: `{}`",
            subdir_path.display(),
            entry.path().display()
        );
    }

    trace!(
        "Size of mirror sub directory `{}`: {}",
        subdir_path.display(),
        dir_size
    );

    dir_size
}

#[must_use]
async fn scan_by_hash_dir(entry: DirEntry) -> u64 {
    let hashdir_path = entry.path();

    trace!(
        "Scanning mirror by-hash directory `{}`...",
        hashdir_path.display()
    );

    let mut hashdir_dir = match tokio::fs::read_dir(&hashdir_path).await {
        Ok(d) => d,
        Err(err) => {
            error!(
                "Error listing mirror by-hash directory `{}`:  {err}",
                hashdir_path.display()
            );
            return 0;
        }
    };

    let mut dir_size = 0;

    while let Some(entry) = match hashdir_dir.next_entry().await {
        Ok(e) => e,
        Err(err) => {
            error!(
                "Error iterating mirror by-hash directory `{}`:  {err}",
                hashdir_path.display()
            );
            return dir_size;
        }
    } {
        let mdata = match entry.metadata().await {
            Ok(d) => d,
            Err(err) => {
                error!(
                    "Error getting file meta data of `{}`:  {err}",
                    entry.path().display()
                );
                continue;
            }
        };

        let file_type = mdata.file_type();

        if file_type.is_file() {
            dir_size += mdata.len();
            continue;
        }

        warn!(
            "Unrecognized entry in mirror by-hash directory `{}`: `{}`",
            hashdir_path.display(),
            entry.path().display()
        );
    }

    trace!(
        "Size of mirror by-hash directory `{}`: {}",
        hashdir_path.display(),
        dir_size
    );

    dir_size
}
