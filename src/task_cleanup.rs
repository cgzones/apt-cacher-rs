use std::{
    ffi::OsString,
    io::ErrorKind,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    os::unix::fs::OpenOptionsExt as _,
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
    AppState, ClientInfo, ProxyCacheBody, ProxyCacheError, RETENTION_TIME,
    cache_layout::{
        CacheLayout, CachedFlavor, ConnectionDetails, SUBDIR_DISTS_BYHASH, SUBDIR_FLAT,
        SUBDIR_FLAT_BYHASH,
    },
    cache_metadata,
    config::Config,
    database::{MirrorEntry, OriginEntry},
    deb_mirror::{Mirror, UriFormat as _, is_deb_package, mirror_cache_path_impl},
    global_cache_quota, global_config,
    humanfmt::HumanFmt,
    info_once, metrics, process_cache_request, task_cache_scan,
};

/// Delay between daemon startup and the first scheduled cleanup run.
pub(crate) const FIRST_CLEANUP_DELAY_SECS: u64 = 60 * 60;

/// Interval between recurring cleanup runs.
pub(crate) const CLEANUP_INTERVAL_SECS: u64 = 24 * 60 * 60;

/// Grace period for unreferenced cached deb files. Apt updates that bypass
/// the proxy register their origin lazily; this delay prevents a freshly
/// cached file from being wiped before its origin row is observed.
const UNREFERENCED_KEEP_SPAN: Duration = Duration::from_hours(3 * 24);

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
    config: &Config,
) -> Result<tokio::fs::File, ProxyCacheError> {
    let mut writer = BufWriter::with_capacity(config.buffer_size, file);

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
        let name = entry.file_name();
        // Mirror `collect_flat_cached_debs`: structured Pool admits
        // `.deb`/`.udeb`/`.ddeb` (see `is_deb_package` in `deb_mirror.rs`),
        // so the cleanup scan must enumerate the same set.
        if name.to_str().is_some_and(is_deb_package) {
            ret.insert(name, entry.path());
        }
    }

    Ok(ret)
}

/// Extract the basename from a `Filename:` line of a Debian Packages stanza.
fn parse_filename_field(line: &str) -> Option<&std::ffi::OsStr> {
    let line = line.trim();
    let filepath = line.strip_prefix("Filename: ")?;
    Path::new(filepath).file_name()
}

/// Decode `hex` into exactly `N` bytes. Returns `None` on wrong length or any
/// non-hexadecimal byte. Accepts upper- and lower-case (Debian uses lowercase
/// but real-world Packages indices have occasionally mixed case).
fn hex_decode_exact<const N: usize>(hex: &str) -> Option<[u8; N]> {
    if hex.len() != N * 2 {
        return None;
    }
    let bytes = hex.as_bytes();
    let mut out = [0u8; N];
    let mut i = 0;
    while i < N {
        let hi = hex_digit(bytes[2 * i])?;
        let lo = hex_digit(bytes[2 * i + 1])?;
        out[i] = (hi << 4) | lo;
        i += 1;
    }
    Some(out)
}

const fn hex_digit(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Parse a Packages stanza line of the form `"<prefix><hex>"` into a fixed-size
/// byte array. Returns `None` if the line does not carry the expected prefix
/// or the hex payload is malformed.
fn parse_hex_field<const N: usize>(line: &str, prefix: &str) -> Option<[u8; N]> {
    let rest = line.trim().strip_prefix(prefix)?.trim_start();
    hex_decode_exact::<N>(rest)
}

/// Lowercase-hex encoding suitable for log messages.
fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(char::from(HEX[(*b >> 4) as usize]));
        out.push(char::from(HEX[(*b & 0x0f) as usize]));
    }
    out
}

/// Hash algorithm we accept from Debian `Packages` stanzas. SHA256 is the
/// universal default in modern indices; SHA512 is used as a fallback when
/// SHA256 is missing.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum HashAlgo {
    Sha256,
    Sha512,
}

impl HashAlgo {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Sha256 => "SHA256",
            Self::Sha512 => "SHA512",
        }
    }
}

/// Outcome of verifying a cache file against an expected digest.
#[derive(Debug)]
enum Verdict {
    /// Computed digest equals the expected one.
    Match,
    /// Computed digest differs from the expected one and the underlying file
    /// did not change inode/size during hashing.
    Mismatch { computed: Vec<u8> },
    /// The file's `(inode, size)` changed between hash start and finish, so a
    /// concurrent writer raced us; the cleanup leaves the file alone.
    Raced,
    /// Open/read failed; cleanup leaves the file alone.
    IoError(std::io::Error),
}

/// Per-call context for [`PackageFormat::reduce_file_list`]: needed to invalidate
/// per-file `cache_metadata` entries and to attribute checksum-mismatch
/// removals back to the per-mirror `CleanupDone` totals.
struct ReduceContext<'a> {
    mirror: &'a Mirror,
    layout: CacheLayout,
    mismatch_files: &'a mut u64,
    mismatch_bytes: &'a mut u64,
}

/// Accumulated state of the current Debian `Packages` stanza.
#[derive(Debug)]
struct Stanza {
    filename: Option<OsString>,
    sha256: Option<[u8; 32]>,
    sha512: Option<[u8; 64]>,
}

impl Stanza {
    const fn new() -> Self {
        Self {
            filename: None,
            sha256: None,
            sha512: None,
        }
    }

    const fn is_empty(&self) -> bool {
        self.filename.is_none() && self.sha256.is_none() && self.sha512.is_none()
    }

    fn reset(&mut self) {
        self.filename = None;
        self.sha256 = None;
        self.sha512 = None;
    }

    fn ingest(&mut self, line: &str) {
        if self.filename.is_none()
            && let Some(name) = parse_filename_field(line)
        {
            self.filename = Some(name.to_os_string());
            return;
        }
        if self.sha256.is_none()
            && let Some(h) = parse_hex_field::<32>(line, "SHA256: ")
        {
            self.sha256 = Some(h);
            return;
        }
        if self.sha512.is_none()
            && let Some(h) = parse_hex_field::<64>(line, "SHA512: ")
        {
            self.sha512 = Some(h);
        }
    }

    /// Preferred (algo, expected-digest) pair: SHA256 wins, SHA512 is the
    /// fallback, `None` means the stanza advertised no usable checksum.
    fn chosen(&self) -> Option<(HashAlgo, Vec<u8>)> {
        if let Some(h) = self.sha256 {
            Some((HashAlgo::Sha256, h.to_vec()))
        } else {
            self.sha512.map(|h| (HashAlgo::Sha512, h.to_vec()))
        }
    }
}

/// Hash the contents of an open file using the given digest algorithm.
/// Synchronous code, blocking the current thread.
fn hash_open_file<D: sha2::Digest>(file: &mut std::fs::File) -> std::io::Result<Vec<u8>> {
    use std::io::Read as _;

    let mut hasher = D::new();
    #[expect(clippy::large_stack_arrays, reason = "ensure efficient file hashing")]
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hasher.finalize().to_vec())
}

/// Blocking digest-and-compare with an inode/size race check after hashing.
/// Runs on the blocking pool via [`verify_cache_file`].
fn verify_file_sync(path: &Path, algo: HashAlgo, expected: &[u8]) -> Verdict {
    use std::os::unix::fs::MetadataExt as _;

    let mut file = match std::fs::File::options()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW)
        .open(path)
    {
        Ok(f) => f,
        Err(err) => return Verdict::IoError(err),
    };
    let pre_meta = match file.metadata() {
        Ok(m) => m,
        Err(err) => return Verdict::IoError(err),
    };
    let pre_ino = pre_meta.ino();
    let pre_size = pre_meta.len();

    let computed = match algo {
        HashAlgo::Sha256 => match hash_open_file::<sha2::Sha256>(&mut file) {
            Ok(h) => h,
            Err(err) => return Verdict::IoError(err),
        },
        HashAlgo::Sha512 => match hash_open_file::<sha2::Sha512>(&mut file) {
            Ok(h) => h,
            Err(err) => return Verdict::IoError(err),
        },
    };

    if computed.as_slice() == expected {
        return Verdict::Match;
    }

    // Race check: a fresh download finishing mid-hash either replaces the
    // file via rename (different inode) or rewrites it in place (size change).
    // Either way our digest is for content no longer at `path`, so bail.
    if let Ok(post_meta) = std::fs::metadata(path)
        && (post_meta.ino() != pre_ino || post_meta.len() != pre_size)
    {
        return Verdict::Raced;
    }
    Verdict::Mismatch { computed }
}

async fn verify_cache_file(path: PathBuf, algo: HashAlgo, expected: Vec<u8>) -> Verdict {
    match tokio::task::spawn_blocking(move || verify_file_sync(&path, algo, &expected)).await {
        Ok(v) => v,
        Err(join_err) => Verdict::IoError(std::io::Error::other(join_err)),
    }
}

/// Process one stanza: if its `Filename:` basename matches a candidate
/// cached file, verify the file content and either retain it (match), warn-
/// and-retain it (no usable hash advertised, transient error, or concurrent
/// rename race), or warn-and-evict it (genuine digest mismatch).
async fn flush_stanza(
    stanza: &mut Stanza,
    file_list: &mut HashMap<OsString, PathBuf>,
    ctx: &mut ReduceContext<'_>,
) {
    let Some(filename) = stanza.filename.take() else {
        stanza.reset();
        return;
    };
    let Some(path) = file_list.get(&filename).cloned() else {
        stanza.reset();
        return;
    };

    match stanza.chosen() {
        None => {
            warn!(
                "Packages stanza for `{}` advertises no SHA256/SHA512; retaining cache file `{}` without verification",
                Path::new(&filename).display(),
                path.display(),
            );
            file_list.remove(&filename);
        }
        Some((algo, expected)) => {
            let pre_size = match tokio::fs::metadata(&path).await {
                Ok(m) => m.len(),
                Err(err) => {
                    error!(
                        "Failed to stat cache file `{}` before {} verification:  {err}; retaining",
                        path.display(),
                        algo.as_str(),
                    );
                    file_list.remove(&filename);
                    stanza.reset();
                    return;
                }
            };
            match verify_cache_file(path.clone(), algo, expected.clone()).await {
                Verdict::Match => {
                    file_list.remove(&filename);
                }
                Verdict::Mismatch { computed } => {
                    warn!(
                        "Cache file `{}` failed {} verification: expected={}, computed={}",
                        path.display(),
                        algo.as_str(),
                        hex_encode(&expected),
                        hex_encode(&computed),
                    );
                    if let Err(err) = tokio::fs::remove_file(&path).await {
                        error!(
                            "Error removing checksum-mismatched cache file `{}`:  {err}",
                            path.display()
                        );
                    } else {
                        if let Some(debname) = path.file_name().and_then(|n| n.to_str()) {
                            cache_metadata::store().invalidate(
                                &cache_metadata::CacheMetadataKeyRef::new(
                                    ctx.mirror, debname, ctx.layout,
                                ),
                            );
                        }
                        metrics::CLEANUP_CHECKSUM_MISMATCHES.increment();
                        *ctx.mismatch_files += 1;
                        *ctx.mismatch_bytes += pre_size;
                    }
                    file_list.remove(&filename);
                }
                Verdict::Raced => {
                    warn!(
                        "Cache file `{}` changed during {} verification; retaining (concurrent re-cache)",
                        path.display(),
                        algo.as_str(),
                    );
                    file_list.remove(&filename);
                }
                Verdict::IoError(err) => {
                    error!(
                        "Failed to {} cache file `{}`:  {err}; retaining",
                        algo.as_str(),
                        path.display(),
                    );
                    file_list.remove(&filename);
                }
            }
        }
    }
    stanza.reset();
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

    /// Stream a (possibly compressed) Debian `Packages` file stanza by stanza,
    /// reducing the candidate `file_list` by basename and verifying matched
    /// cache files against the stanza's `SHA256:`/`SHA512:` digest.
    async fn reduce_file_list(
        self,
        file: tokio::fs::File,
        filename: &str,
        file_list: &mut HashMap<OsString, PathBuf>,
        ctx: &mut ReduceContext<'_>,
        config: &Config,
    ) -> Result<(), ProxyCacheError> {
        debug_assert!(!file_list.is_empty(), "avoid unnecessary work");

        let buffer_size = config.buffer_size;

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
        let mut stanza = Stanza::new();
        loop {
            buffer.clear();
            match reader.read_line(&mut buffer).await {
                Ok(0) => {
                    // Flush the final stanza if the Packages file doesn't end
                    // with a blank line.
                    if !stanza.is_empty() {
                        flush_stanza(&mut stanza, file_list, ctx).await;
                    }
                    return Ok(());
                }
                Err(err) => {
                    error!("Failed to read in-memory file `{filename}`:  {err}");
                    return Err(err.into());
                }
                Ok(_bytes_read) => {
                    if buffer.trim().is_empty() {
                        flush_stanza(&mut stanza, file_list, ctx).await;
                        if file_list.is_empty() {
                            return Ok(());
                        }
                        continue;
                    }
                    stanza.ingest(&buffer);
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
            layout: CacheLayout::Dists,
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

    let config = global_config();

    let start = Instant::now();

    if let Err(err) = appstate.database.cleanup_invalid_rows().await {
        metrics::DB_OPERATION_FAILED.increment();
        error!("Failed to clean up invalid database rows:  {err}");
    }

    if let Some(usage_retention_days) = config.usage_retention_days {
        let retention_secs = usage_retention_days
            .get()
            .checked_mul(24 * 60 * 60)
            .expect("overflow check during config parsing");
        let now_secs = coarsetime::Clock::now_since_epoch().as_secs();
        let keep_date = Duration::from_secs(now_secs.saturating_sub(retention_secs));
        if let Err(err) = appstate.database.delete_usage_logs(keep_date).await {
            metrics::DB_OPERATION_FAILED.increment();
            error!("Failed to delete old usage logs:  {err}");
        }
    }

    let mirrors = appstate.database.get_mirrors().await.inspect_err(|err| {
        metrics::DB_OPERATION_FAILED.increment();
        error!("Error looking up hosts:  {err}");
        // Earlier steps in this task (cleanup_invalid_rows /
        // delete_usage_logs) may already have run, but no per-mirror
        // cleanup work was done; record the failed-run state so the
        // dashboard does not display stale prior-run values.
        let elapsed = start.elapsed();
        metrics::LAST_CLEANUP_DURATION_SECS.set(elapsed.as_secs());
        metrics::LAST_CLEANUP_FILES_REMOVED.set(0);
        metrics::LAST_CLEANUP_BYTES_RECLAIMED.set(0);
    })?;

    trace!("Mirrors ({}): {mirrors:?}", mirrors.len());
    info!("Found {} mirrors for cleanup", mirrors.len());

    cleanup_stale_partials(&config.cache_directory, &mirrors).await;

    // Create a stream of futures for structured deb files, flat deb files,
    // and by-hash files cleanup.
    let cleanup_tasks = mirrors.into_iter().flat_map(|mirror| {
        [
            tokio::task::spawn(cleanup_mirror_deb_files(
                mirror.clone(),
                appstate.clone(),
                config,
            )),
            tokio::task::spawn(cleanup_mirror_flat_files(
                mirror.clone(),
                appstate.clone(),
                config,
            )),
            tokio::task::spawn(cleanup_mirror_byhash_files(mirror, config)),
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
            metrics::DB_OPERATION_FAILED.increment();
            error!("Error setting cleanup timestamp:  {err}");
        }

        files_retained += cleanup_result.files_retained;
        files_removed += cleanup_result.files_removed;
        bytes_removed += cleanup_result.bytes_removed;
    }

    if let Ok(actual_cache_size) = task_cache_scan(&appstate.database).await {
        let active_downloading_size = appstate.active_downloads.download_size();

        let quota = global_cache_quota();
        let (stored, csize, difference) =
            quota.subtract_and_reconcile(bytes_removed, actual_cache_size, active_downloading_size);

        if difference != 0 {
            warn!(
                "Repaired cache size discrepancy of {difference}: actual={actual_cache_size} stored={stored} corrected={csize} active={active_downloading_size}"
            );
        } else {
            debug!(
                "actual cache size: {actual_cache_size}; stored cache size: {stored}; active download size: {active_downloading_size}"
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
    config: &Config,
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

    let mirror_path: PathBuf = [&config.cache_directory, &mirror.cache_path()]
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

    let mirror = mirror.into();

    if cached_files.is_empty() {
        return Ok(CleanupDone {
            mirror,
            files_retained: num_total_files,
            files_removed: 0,
            bytes_removed: 0,
        });
    }

    let mut mismatch_files: u64 = 0;
    let mut mismatch_bytes: u64 = 0;

    for origin in &active_origins {
        let (mut response, pkgfmt) = match get_package_file(&mirror, origin, &appstate).await {
            // A missing Packages file leaves us unable to complete the
            // reference set; deleting now risks wiping files referenced
            // only by this origin (typical when a distribution goes EOL
            // upstream). Bail conservatively and retry next cycle.
            Err(status) => {
                warn!(
                    "Could not fetch package file for {origin:?} ({status}); skipping cleanup for mirror {mirror}"
                );

                return Ok(CleanupDone {
                    mirror,
                    files_retained: num_total_files - mismatch_files,
                    files_removed: mismatch_files,
                    bytes_removed: mismatch_bytes,
                });
            }
            Ok(r) => r,
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

        let file = body_to_file(response.body_mut(), file, config)
            .await
            .inspect_err(|err| {
                error!("Failed to write response to in-memory file `{memfdname}`:  {err}");
            })?;

        {
            let mut ctx = ReduceContext {
                mirror: &mirror,
                layout: CacheLayout::StructuredPool,
                mismatch_files: &mut mismatch_files,
                mismatch_bytes: &mut mismatch_bytes,
            };
            pkgfmt
                .reduce_file_list(file, &memfdname, &mut cached_files, &mut ctx, config)
                .await?;
        }

        if cached_files.is_empty() {
            return Ok(CleanupDone {
                mirror,
                files_retained: num_total_files - mismatch_files,
                files_removed: mismatch_files,
                bytes_removed: mismatch_bytes,
            });
        }
    }

    let mut aged_files: u64 = 0;
    let mut aged_bytes: u64 = 0;
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
                && existing_for < UNREFERENCED_KEEP_SPAN
            {
                debug!(
                    "Keeping unreferenced file `{}` since it is too new ({}, threshold={})",
                    path.display(),
                    HumanFmt::Time(existing_for),
                    HumanFmt::Time(UNREFERENCED_KEEP_SPAN)
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

        // Drop the post-flight ETag/Last-Modified entry so a re-cache
        // starts clean.  A concurrent re-download finishing between
        // `remove_file` and `invalidate` loses its fresh `set()`; the
        // next request re-populates from xattr.  Non-UTF-8 filenames
        // are opaque (debnames are URL-decoded ASCII; mismatches aren't
        // in the map).
        if let Some(debname) = path.file_name().and_then(|n| n.to_str()) {
            cache_metadata::store().invalidate(&cache_metadata::CacheMetadataKeyRef::new(
                &mirror,
                debname,
                CacheLayout::StructuredPool,
            ));
        }

        debug!("Removed unreferenced file `{}`", path.display());

        aged_bytes += size;
        aged_files += 1;
    }

    info!(
        "Removed {aged_files} unreferenced deb files for mirror {mirror} ({})",
        HumanFmt::Size(aged_bytes)
    );

    let files_removed = mismatch_files + aged_files;
    let bytes_removed = mismatch_bytes + aged_bytes;

    Ok(CleanupDone {
        mirror,
        files_retained: num_total_files - files_removed,
        files_removed,
        bytes_removed,
    })
}

/// Collect Debian binary packages (`.deb`, `.udeb`, `.ddeb`) from the flat
/// subdirectory.  Metadata files (`InRelease`, `Packages*`, ...) and the
/// `by-hash/` subtree are filtered out by the extension check.
async fn collect_flat_cached_debs(
    flat_path: &Path,
) -> Result<HashMap<OsString, PathBuf>, ProxyCacheError> {
    let mut ret = HashMap::new();

    let mut dir = match tokio::fs::read_dir(flat_path).await {
        Ok(d) => d,
        Err(err) if err.kind() == ErrorKind::NotFound => return Ok(ret),
        Err(err) => return Err(ProxyCacheError::Io(err)),
    };

    while let Some(entry) = dir.next_entry().await? {
        let name = entry.file_name();
        if name.to_str().is_some_and(is_deb_package) {
            ret.insert(name, entry.path());
        }
    }

    Ok(ret)
}

/// Fetch the flat Packages file for a mirror, trying `Packages.xz`,
/// `Packages.gz`, then raw `Packages`.  Mirrors `get_package_file` but for the
/// dist/comp/arch-less flat layout.
async fn get_flat_packages_file(
    mirror: &Mirror,
    appstate: &AppState,
) -> Result<(Response<ProxyCacheBody>, PackageFormat), StatusCode> {
    let authority = mirror.format_authority();
    let mirror_path = mirror.path();
    let base_uri = format!("http://{authority}/{mirror_path}/Packages");

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
            debname: format!("Packages{}", pkgfmt.extension()),
            cached_flavor: CachedFlavor::Volatile,
            layout: CacheLayout::Flat,
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

/// Remove cached deb files in `cached_files` that are older than `keep_span`,
/// dropping any matching `cache_metadata` entries on success.
///
/// Used by the flat-cleanup path both when a Packages index has reduced the
/// map down to genuinely-unreferenced files (short span) and as a fallback
/// when the Packages index is unfetchable (long span, since we cannot tell
/// which entries are still referenced).
async fn sweep_aged_cached_debs(
    cached_files: &HashMap<OsString, PathBuf>,
    keep_span: Duration,
    mirror: &Mirror,
    layout: CacheLayout,
) -> (u64, u64) {
    let mut bytes_removed = 0u64;
    let mut files_removed = 0u64;
    let now = SystemTime::now();

    for path in cached_files.values() {
        let data = match tokio::fs::metadata(path).await {
            Ok(d) => Some(d),
            Err(err) => {
                error!("Error inspecting cached file `{}`:  {err}", path.display());
                None
            }
        };

        if let Some(data) = &data {
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
                && existing_for < keep_span
            {
                debug!(
                    "Keeping cached file `{}` since it is too new ({}, threshold={})",
                    path.display(),
                    HumanFmt::Time(existing_for),
                    HumanFmt::Time(keep_span)
                );
                continue;
            }
        }

        let size = match &data {
            Some(d) => d.len(),
            None => 0,
        };

        if let Err(err) = tokio::fs::remove_file(&path).await {
            error!("Error removing cached file `{}`:  {err}", path.display());
            continue;
        }

        if let Some(debname) = path.file_name().and_then(|n| n.to_str()) {
            cache_metadata::store().invalidate(&cache_metadata::CacheMetadataKeyRef::new(
                mirror, debname, layout,
            ));
        }

        debug!("Removed cached file `{}`", path.display());

        bytes_removed += size;
        files_removed += 1;
    }

    (files_removed, bytes_removed)
}

async fn cleanup_mirror_flat_files(
    mirror: MirrorEntry,
    appstate: AppState,
    config: &Config,
) -> Result<CleanupDone, ProxyCacheError> {
    let mirror_cache_path = mirror.cache_path();
    let flat_path: PathBuf = [
        &config.cache_directory,
        &mirror_cache_path,
        Path::new(SUBDIR_FLAT),
    ]
    .iter()
    .collect();

    // Probe: skip mirrors that have no flat subtree.  Flat-only mirrors are
    // discovered through the regular `get_mirrors` query because every served
    // file (including the first flat .deb) writes a Delivery row that
    // upserts the mirror id.
    match tokio::fs::metadata(&flat_path).await {
        Ok(_) => {}
        Err(err) if err.kind() == ErrorKind::NotFound => {
            return Ok(CleanupDone {
                mirror: mirror.into(),
                files_retained: 0,
                files_removed: 0,
                bytes_removed: 0,
            });
        }
        Err(err) => {
            error!(
                "Error probing flat directory `{}`:  {err}",
                flat_path.display()
            );
            return Err(ProxyCacheError::Io(err));
        }
    }

    let mut cached_files = collect_flat_cached_debs(&flat_path)
        .await
        .inspect_err(|err| {
            error!("Error listing files in `{}`:  {err}", flat_path.display());
        })?;

    let num_total_files = cached_files.len() as u64;

    let mirror: Mirror = mirror.into();

    info!(
        "Found {} cached flat deb files for mirror {mirror}",
        cached_files.len(),
    );

    if cached_files.is_empty() {
        return Ok(CleanupDone {
            mirror,
            files_retained: num_total_files,
            files_removed: 0,
            bytes_removed: 0,
        });
    }

    let (mut response, pkgfmt) = match get_flat_packages_file(&mirror, &appstate).await {
        Ok(r) => r,
        Err(status) => {
            // Flat caching can mint a `MirrorEntry` for any nested deb URL
            // (e.g. `apt/sub/pkg_..._amd64.deb`), which means a mirror path
            // may legitimately have cached debs but no co-located Packages
            // index. Without a fallback those debs would never be GC'd. Fall
            // back to a long time-based retention so abandoned/typo'd flat
            // mirror paths eventually drain instead of accumulating forever.
            warn!(
                "Could not fetch flat Packages file for mirror {mirror} ({status}); falling back to {} time-based retention",
                HumanFmt::Time(RETENTION_TIME),
            );
            let (files_removed, bytes_removed) =
                sweep_aged_cached_debs(&cached_files, RETENTION_TIME, &mirror, CacheLayout::Flat)
                    .await;
            info!(
                "Removed {files_removed} aged flat deb files for mirror {mirror} ({})",
                HumanFmt::Size(bytes_removed)
            );
            return Ok(CleanupDone {
                mirror,
                files_retained: num_total_files - files_removed,
                files_removed,
                bytes_removed,
            });
        }
    };

    let memfdname = format!("flat_packages{}", pkgfmt.extension());

    let memfd = MemfdOptions::new().create(&memfdname).map_err(|err| {
        error!("Error creating in-memory file `{memfdname}`:  {err}");
        ProxyCacheError::Memfd(err)
    })?;

    let file = tokio::fs::File::from_std(memfd.into_file());

    let file = body_to_file(response.body_mut(), file, config)
        .await
        .inspect_err(|err| {
            error!("Failed to write response to in-memory file `{memfdname}`:  {err}");
        })?;

    let mut mismatch_files: u64 = 0;
    let mut mismatch_bytes: u64 = 0;
    {
        let mut ctx = ReduceContext {
            mirror: &mirror,
            layout: CacheLayout::Flat,
            mismatch_files: &mut mismatch_files,
            mismatch_bytes: &mut mismatch_bytes,
        };
        pkgfmt
            .reduce_file_list(file, &memfdname, &mut cached_files, &mut ctx, config)
            .await?;
    }

    if cached_files.is_empty() {
        return Ok(CleanupDone {
            mirror,
            files_retained: num_total_files - mismatch_files,
            files_removed: mismatch_files,
            bytes_removed: mismatch_bytes,
        });
    }

    let (aged_files, aged_bytes) = sweep_aged_cached_debs(
        &cached_files,
        UNREFERENCED_KEEP_SPAN,
        &mirror,
        CacheLayout::Flat,
    )
    .await;

    let files_removed = mismatch_files + aged_files;
    let bytes_removed = mismatch_bytes + aged_bytes;

    info!(
        "Removed {aged_files} unreferenced flat deb files for mirror {mirror} ({})",
        HumanFmt::Size(aged_bytes)
    );

    Ok(CleanupDone {
        mirror,
        files_retained: num_total_files - files_removed,
        files_removed,
        bytes_removed,
    })
}

/// Result of a single by-hash directory walk.
#[derive(Default)]
struct ByHashStats {
    files_retained: u64,
    files_removed: u64,
    bytes_removed: u64,
}

/// Walk a single by-hash directory, removing entries older than `keep_span`.
/// `NotFound` is treated as "nothing to do" so the caller can probe both the
/// structured and flat layouts without pre-checking either.
///
/// `mirror` and `layout` identify the in-memory `cache_metadata` keys to drop
/// alongside each removed file. Without this, the resolve-side cache would
/// retain entries for GC'd hashes and grow unbounded over long uptimes.
async fn cleanup_byhash_dir(
    byhash_path: &Path,
    keep_span: Duration,
    now: SystemTime,
    mirror: &Mirror,
    layout: CacheLayout,
) -> Result<ByHashStats, ProxyCacheError> {
    let mut stats = ByHashStats::default();

    let mut byhash_dir = match tokio::fs::read_dir(byhash_path).await {
        Ok(d) => d,
        Err(err) if err.kind() == ErrorKind::NotFound => {
            debug!(
                "Directory `{}` not found. Cleanup skipped.",
                byhash_path.display()
            );
            return Ok(stats);
        }
        Err(err) => {
            error!(
                "Error traversing directory `{}`:  {}",
                byhash_path.display(),
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

        stats.files_retained += 1;

        let metadata = match entry.metadata().await {
            Ok(d) => d,
            Err(err) => {
                error!("Error inspecting file `{}`:  {err}", path.display());
                continue;
            }
        };

        let modified = match metadata.modified() {
            Ok(m) => m,
            Err(err) => {
                error!("Failed to get mtime of file `{}`:  {err}", path.display());
                continue;
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

        if let Some(debname) = path.file_name().and_then(|n| n.to_str()) {
            cache_metadata::store().invalidate(&cache_metadata::CacheMetadataKeyRef::new(
                mirror, debname, layout,
            ));
        }

        stats.bytes_removed += metadata.len();
        stats.files_removed += 1;
        stats.files_retained -= 1;
    }

    Ok(stats)
}

async fn cleanup_mirror_byhash_files(
    mirror: MirrorEntry,
    config: &Config,
) -> Result<CleanupDone, ProxyCacheError> {
    let now = SystemTime::now();
    let keep_span = Duration::from_secs(24 * 60 * 60 * config.byhash_retention_days.get());
    let mirror_cache_path = mirror.cache_path();
    let mirror: Mirror = mirror.into();

    let mut total = ByHashStats::default();

    // Walk both the structured (`dists/by-hash`) and flat (`flat/by-hash`)
    // layouts.  Each call short-circuits on `NotFound`, so a mirror with only
    // one layout pays only a stat call for the missing one.
    for (sub, layout) in [
        (SUBDIR_DISTS_BYHASH, CacheLayout::DistsByHash),
        (SUBDIR_FLAT_BYHASH, CacheLayout::FlatByHash),
    ] {
        let path: PathBuf = [&config.cache_directory, &mirror_cache_path, Path::new(sub)]
            .iter()
            .collect();

        let stats = cleanup_byhash_dir(&path, keep_span, now, &mirror, layout).await?;
        total.files_retained += stats.files_retained;
        total.files_removed += stats.files_removed;
        total.bytes_removed += stats.bytes_removed;
    }

    info!(
        "Removed {} files acquired by-hash for mirror {mirror} ({})",
        total.files_removed,
        HumanFmt::Size(total.bytes_removed)
    );

    Ok(CleanupDone {
        mirror,
        files_retained: total.files_retained,
        files_removed: total.files_removed,
        bytes_removed: total.bytes_removed,
    })
}

/// Remove stale entries from each mirror's `tmp/` directory.
///
/// Iterates known mirror directories directly (rather than walking the entire
/// cache tree) and delegates to [`cleanup_tmp_dir`] for the per-directory
/// policy.
async fn cleanup_stale_partials(cache_dir: &Path, mirrors: &[MirrorEntry]) {
    let now = SystemTime::now();
    let mut removed = 0u64;

    for mirror in mirrors {
        let mirror_dir = mirror_cache_path_impl(&mirror.host, mirror.port(), &mirror.path);
        let tmp_dir: PathBuf = [cache_dir, mirror_dir.as_path(), Path::new("tmp")]
            .iter()
            .collect();
        removed += cleanup_tmp_dir(&tmp_dir, now).await;
    }

    if removed > 0 {
        info!("Removed {removed} stale tmp file(s)");
    }
}

/// Remove stale entries from a single `tmp/` directory.
///
/// `.partial` files are deleted when zero-byte (no useful resume state) or
/// older than `PARTIAL_MAX_AGE`. Any other artifact (defensive — current code
/// only writes `.partial` here) is deleted once it has aged past
/// `FOREIGN_MAX_AGE`, the longer threshold acknowledging that we don't know
/// what produced it.
async fn cleanup_tmp_dir(tmp_dir: &Path, now: SystemTime) -> u64 {
    const PARTIAL_MAX_AGE: Duration = Duration::from_hours(3 * 24);
    const FOREIGN_MAX_AGE: Duration = Duration::from_hours(7 * 24);

    let partial_cutoff = now - PARTIAL_MAX_AGE;
    let foreign_cutoff = now - FOREIGN_MAX_AGE;

    let mut entries = match tokio::fs::read_dir(tmp_dir).await {
        Ok(e) => e,
        Err(err) if err.kind() == ErrorKind::NotFound => {
            return 0;
        }
        Err(err) => {
            error!(
                "Failed to read tmp directory `{}`:  {err}",
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
                    "Failed to iterate tmp directory `{}`:  {err}",
                    tmp_dir.display()
                );
                break;
            }
        };

        let name = entry.file_name();
        let Some(name_str) = name.to_str() else {
            error!("Failed to decode name of tmp file `{}`", name.display());
            continue;
        };

        let file_type = match entry.file_type().await {
            Ok(ft) => ft,
            Err(err) => {
                error!("Failed to get file type of tmp entry `{name_str}`:  {err}");
                continue;
            }
        };

        let md = match entry.metadata().await {
            Ok(m) => m,
            Err(err) => {
                error!("Failed to stat tmp file `{name_str}`:  {err}");
                continue;
            }
        };

        let mtime = md.modified().unwrap_or(SystemTime::UNIX_EPOCH);
        // Apply the per-suffix `.partial` policy only to regular files: a
        // symlink-to-dir or a stray directory named `*.partial` should not
        // be measured by `len()` (zero for a symlink) and should be reaped
        // under the longer foreign cutoff instead.
        let is_partial = file_type.is_file() && name_str.ends_with(".partial");
        let should_remove = if is_partial {
            // Zero-byte partials carry no resume state; aged partials are stale.
            md.len() == 0 || mtime < partial_cutoff
        } else if mtime < foreign_cutoff {
            true
        } else {
            debug!("Keeping unexpected tmp entry `{name_str}` (not yet past foreign cutoff)");
            continue;
        };

        if should_remove {
            let path = entry.path();
            // The tmp/ producer (`download_file`) only writes regular
            // files, so a directory or symlink here is unexpected — but
            // `remove_file` would fail on a real directory and re-fail
            // every cleanup pass.  Dispatch on `file_type.is_dir()` (which,
            // unlike `Metadata::is_dir`, is unambiguous about not following
            // symlinks) so a real directory is recursively cleaned up while
            // a symlink-to-dir is unlinked via `remove_file` rather than
            // having `remove_dir_all` traverse its target.
            let removal = if file_type.is_dir() {
                tokio::fs::remove_dir_all(&path).await
            } else {
                tokio::fs::remove_file(&path).await
            };
            if let Err(err) = removal {
                error!(
                    "Failed to remove stale tmp entry `{}`:  {err}",
                    path.display()
                );
            } else {
                debug!("Removed stale tmp entry `{}`", path.display());
                removed += 1;
            }
        }
    }

    removed
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsStr;

    #[test]
    fn parse_filename_field_strips_lf() {
        assert_eq!(
            parse_filename_field("Filename: pool/main/a/abc/abc_1.0_amd64.deb\n"),
            Some(OsStr::new("abc_1.0_amd64.deb")),
        );
    }

    #[test]
    fn parse_filename_field_strips_crlf() {
        assert_eq!(
            parse_filename_field("Filename: pool/main/a/abc/abc_1.0_amd64.deb\r\n"),
            Some(OsStr::new("abc_1.0_amd64.deb")),
        );
    }

    #[test]
    fn parse_filename_field_no_terminator() {
        assert_eq!(
            parse_filename_field("Filename: pool/main/a/abc/abc_1.0_amd64.deb"),
            Some(OsStr::new("abc_1.0_amd64.deb")),
        );
    }

    #[test]
    fn parse_filename_field_handles_udeb_extension() {
        assert_eq!(
            parse_filename_field("Filename: pool/main/i/inst/inst_1.0_amd64.udeb\n"),
            Some(OsStr::new("inst_1.0_amd64.udeb")),
        );
    }

    #[test]
    fn parse_filename_field_skips_other_keys() {
        assert_eq!(parse_filename_field("Package: stub\n"), None);
        assert_eq!(parse_filename_field("\n"), None);
        assert_eq!(parse_filename_field(""), None);
    }

    #[test]
    fn hex_decode_exact_round_trip_lowercase() {
        let bytes: [u8; 4] = [0xde, 0xad, 0xbe, 0xef];
        let s = hex_encode(&bytes);
        assert_eq!(s, "deadbeef");
        assert_eq!(hex_decode_exact::<4>(&s), Some(bytes));
    }

    #[test]
    fn hex_decode_exact_accepts_uppercase() {
        assert_eq!(
            hex_decode_exact::<4>("DEADBEEF"),
            Some([0xde, 0xad, 0xbe, 0xef])
        );
    }

    #[test]
    fn hex_decode_exact_rejects_wrong_length() {
        assert_eq!(hex_decode_exact::<4>("deadbe"), None); // too short
        assert_eq!(hex_decode_exact::<4>("deadbeef00"), None); // too long
    }

    #[test]
    fn hex_decode_exact_rejects_non_hex() {
        assert_eq!(hex_decode_exact::<4>("deadbeeg"), None);
        assert_eq!(hex_decode_exact::<4>("deadbe!f"), None);
    }

    #[test]
    fn parse_hex_field_sha256() {
        let hash = [0x11u8; 32];
        let line = format!("SHA256: {}\n", hex_encode(&hash));
        assert_eq!(parse_hex_field::<32>(&line, "SHA256: "), Some(hash));
    }

    #[test]
    fn parse_hex_field_sha512() {
        let hash = [0x22u8; 64];
        let line = format!("SHA512:  {}\r\n", hex_encode(&hash));
        assert_eq!(parse_hex_field::<64>(&line, "SHA512: "), Some(hash));
    }

    #[test]
    fn parse_hex_field_rejects_wrong_prefix() {
        let line = format!("MD5sum: {}\n", hex_encode(&[0u8; 32]));
        assert_eq!(parse_hex_field::<32>(&line, "SHA256: "), None);
    }

    #[test]
    fn parse_hex_field_rejects_malformed_payload() {
        // 63 hex chars (one short of 64); should fail length check.
        let payload = "0".repeat(63);
        let line = format!("SHA256: {payload}\n");
        assert_eq!(parse_hex_field::<32>(&line, "SHA256: "), None);
    }

    #[test]
    fn stanza_ingest_collects_filename_and_sha256() {
        let mut s = Stanza::new();
        s.ingest("Filename: pool/main/a/abc/abc_1.0_amd64.deb\n");
        s.ingest(&format!("SHA256: {}\n", hex_encode(&[0xab; 32])));
        assert_eq!(s.filename.as_deref(), Some(OsStr::new("abc_1.0_amd64.deb")));
        assert_eq!(s.chosen(), Some((HashAlgo::Sha256, vec![0xab; 32])));
    }

    #[test]
    fn stanza_chosen_prefers_sha256_over_sha512() {
        let mut s = Stanza::new();
        s.sha256 = Some([0x11u8; 32]);
        s.sha512 = Some([0x22u8; 64]);
        assert_eq!(s.chosen(), Some((HashAlgo::Sha256, vec![0x11u8; 32])));
    }

    #[test]
    fn stanza_chosen_falls_back_to_sha512() {
        let mut s = Stanza::new();
        s.sha512 = Some([0x33u8; 64]);
        assert_eq!(s.chosen(), Some((HashAlgo::Sha512, vec![0x33u8; 64])));
    }

    #[test]
    fn stanza_chosen_returns_none_without_hash() {
        let s = Stanza::new();
        assert_eq!(s.chosen(), None);
    }

    #[test]
    fn stanza_ingest_ignores_unrelated_lines() {
        let mut s = Stanza::new();
        s.ingest("Package: stub\n");
        s.ingest("Description: a stub\n");
        s.ingest(" continued description text\n");
        assert!(s.is_empty());
    }

    #[test]
    fn verify_file_sync_match_and_mismatch() {
        use sha2::Digest as _;
        use std::io::Write as _;

        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("cache.deb");
        let payload = b"hello apt-cacher-rs world";
        {
            let mut f = std::fs::File::create(&path).expect("create");
            f.write_all(payload).expect("write");
        }

        let expected_sha256 = sha2::Sha256::digest(payload).to_vec();
        assert!(matches!(
            verify_file_sync(&path, HashAlgo::Sha256, &expected_sha256),
            Verdict::Match
        ));

        let wrong: Vec<u8> = vec![0u8; 32];
        let v = verify_file_sync(&path, HashAlgo::Sha256, &wrong);
        let Verdict::Mismatch { computed } = v else {
            unreachable!("expected Mismatch verdict, got {v:?}")
        };
        assert_eq!(computed, expected_sha256);

        let expected_sha512 = sha2::Sha512::digest(payload).to_vec();
        assert!(matches!(
            verify_file_sync(&path, HashAlgo::Sha512, &expected_sha512),
            Verdict::Match
        ));
    }

    #[test]
    fn verify_file_sync_io_error_on_missing_path() {
        let dir = tempfile::tempdir().expect("tempdir");
        let missing = dir.path().join("does_not_exist");
        assert!(matches!(
            verify_file_sync(&missing, HashAlgo::Sha256, &[0u8; 32]),
            Verdict::IoError(_)
        ));
    }
}
