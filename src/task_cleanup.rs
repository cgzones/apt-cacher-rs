use std::{
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
        CacheLayout, CachedFlavor, ConnectionDetails, SUBDIR_DISTS_BYHASH, SUBDIR_FLAT_BYHASH,
        SUBDIR_TMP,
    },
    cache_metadata,
    config::{Config, DomainName},
    database::MirrorEntry,
    deb_mirror::{
        Mirror, UriFormat as _, is_deb_package, is_strict_path_descendant, mirror_cache_path_impl,
        path_starts_with_segment,
    },
    global_cache_quota, global_config,
    humanfmt::HumanFmt,
    info_once, metrics, process_cache_request, task_cache_scan,
    utils::probe_dir,
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

/// Drop the in-memory `cache_metadata` entry keyed by `(mirror, basename, layout)`.
/// Non-UTF-8 filenames are silently skipped: debnames are URL-decoded ASCII,
/// so any non-UTF-8 path can't be in the metadata store to begin with.
fn invalidate_metadata_for(path: &Path, mirror: &Mirror, layout: CacheLayout) {
    if let Some(debname) = path.file_name().and_then(|n| n.to_str()) {
        cache_metadata::store().invalidate(&cache_metadata::CacheMetadataKeyRef::new(
            mirror, debname, layout,
        ));
    }
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

async fn packages_body_to_memfd(
    memfdname: &str,
    body: &mut ProxyCacheBody,
    config: &Config,
) -> Result<tokio::fs::File, ProxyCacheError> {
    let memfd = MemfdOptions::new().create(memfdname).map_err(|err| {
        error!("Error creating in-memory file `{memfdname}`:  {err}");
        ProxyCacheError::Memfd(err)
    })?;
    let file = tokio::fs::File::from_std(memfd.into_file());
    body_to_file(body, file, config).await.inspect_err(|err| {
        error!("Failed to write response to in-memory file `{memfdname}`:  {err}");
    })
}

async fn collect_cached_files(
    host_path: &Path,
) -> Result<HashMap<String, PathBuf>, ProxyCacheError> {
    let mut ret = HashMap::new();

    let mut host_dir = match tokio::fs::read_dir(host_path).await {
        Ok(d) => d,
        Err(err) if err.kind() == ErrorKind::NotFound => return Ok(ret),
        Err(err) => {
            metrics::CACHE_IO_FAILURE.increment();
            error!("Failed to read directory `{}`:  {err}", host_path.display());
            return Err(ProxyCacheError::Io(err));
        }
    };

    loop {
        let entry = match host_dir.next_entry().await {
            Ok(Some(e)) => e,
            Ok(None) => break,
            Err(err) => {
                metrics::CACHE_IO_FAILURE.increment();
                error!(
                    "Failed to iterate directory `{}`:  {err}",
                    host_path.display()
                );
                return Err(ProxyCacheError::Io(err));
            }
        };
        let name = entry.file_name();
        let Some(name_str) = name.to_str() else {
            warn!(
                "Unrecognized entry in mirror pool directory: `{}`",
                entry.path().display()
            );
            continue;
        };
        // Mirror `collect_flat_cached_debs`: structured Pool admits
        // `.deb`/`.udeb`/`.ddeb` (see `is_deb_package` in `deb_mirror.rs`),
        // so the cleanup scan must enumerate the same set.
        if !is_deb_package(name_str) {
            continue;
        }

        let file_type = match entry.file_type().await {
            Ok(ft) => ft,
            Err(err) => {
                metrics::CACHE_IO_FAILURE.increment();
                error!(
                    "Failed to get file type of `{}`:  {err}",
                    entry.path().display()
                );
                continue;
            }
        };
        if !file_type.is_file() {
            metrics::CACHE_NON_REGULAR.increment();
            let path = entry.path();
            if file_type.is_dir() {
                warn!(
                    "Skipping unexpected directory in mirror pool directory: `{}`",
                    path.display()
                );
            } else {
                warn!(
                    "Removing non-regular entry in mirror pool directory: `{}`",
                    path.display()
                );
                if let Err(err) = tokio::fs::remove_file(&path).await {
                    metrics::CACHE_IO_FAILURE.increment();
                    error!(
                        "Failed to remove non-regular entry `{}`:  {err}",
                        path.display()
                    );
                } else {
                    debug!("Removed non-regular entry `{}`", path.display());
                }
            }
            continue;
        }

        ret.insert(name_str.to_owned(), entry.path());
    }

    Ok(ret)
}

/// Extract the `Filename:` field's relative-path value from a Debian
/// `Packages` stanza line.  Returns the path verbatim (e.g.
/// `pool/main/a/abc/abc_1.0_amd64.deb` for a structured archive, or
/// `amd64/twilio_5.0.0_amd64.deb` for a flat repo with a sub-arch layout).
///
/// **Security**: rejects empty values, absolute paths, NUL bytes, backslash,
/// and any segment equal to `..` or `.`.  An attacker-controlled upstream
/// Packages stanza could otherwise inject a traversal sequence; rejecting
/// here keeps the downstream `HashMap` key honest even if a later refactor
/// joins it to a filesystem path.
fn parse_filename_field(line: &str) -> Option<&str> {
    let line = line.trim();
    let filepath = line.strip_prefix("Filename: ")?.trim_start();
    if !is_safe_filename_relpath(filepath) {
        return None;
    }
    Some(filepath)
}

/// `true` iff `s` is a safe relative path: non-empty, no leading `/`, no
/// backslash, no ASCII control character (`< 0x20`, plus `0x7f` DEL), and
/// every `/`-separated segment is non-empty and not `.` or `..`.
fn is_safe_filename_relpath(s: &str) -> bool {
    if s.is_empty() || s.starts_with('/') {
        return false;
    }
    if s.bytes().any(|b| b < 0x20 || b == 0x7f || b == b'\\') {
        return false;
    }
    s.split('/')
        .all(|seg| !seg.is_empty() && seg != "." && seg != "..")
}

/// Derive the on-disk cache key for a structured-pool entry.  Structured
/// pool URLs flatten the long `pool/main/<l>/<pkg>/` URL path to just the
/// `.deb` basename on disk, so cleanup matches `Filename:` stanzas by the
/// basename portion only.  Borrows from `relpath` to avoid allocating a
/// fresh `String` per matched stanza.
fn structured_lookup_key(relpath: &str) -> Option<&str> {
    Path::new(relpath).file_name().and_then(|n| n.to_str())
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
    /// Full relative-path value from the `Filename:` field, validated by
    /// [`is_safe_filename_relpath`].  Structured cleanup derives the on-
    /// disk lookup key from this via [`structured_lookup_key`]; flat
    /// cleanup uses it verbatim.
    filename: Option<String>,
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
            self.filename = Some(name.to_owned());
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
    /// Returns a borrow into the stanza so a hot Packages scan does not
    /// allocate a fresh `Vec<u8>` per matched stanza.
    fn chosen(&self) -> Option<(HashAlgo, &[u8])> {
        if let Some(h) = self.sha256.as_ref() {
            Some((HashAlgo::Sha256, h.as_slice()))
        } else {
            self.sha512
                .as_ref()
                .map(|h| (HashAlgo::Sha512, h.as_slice()))
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
        Err(err) => {
            metrics::CACHE_IO_FAILURE.increment();
            return Verdict::IoError(err);
        }
    };
    let pre_meta = match file.metadata() {
        Ok(m) if m.file_type().is_file() => m,
        Ok(_) => {
            metrics::CACHE_NON_REGULAR.increment();
            return Verdict::IoError(std::io::Error::new(
                ErrorKind::InvalidData,
                "Not a regular file",
            ));
        }
        Err(err) => {
            metrics::CACHE_IO_FAILURE.increment();
            return Verdict::IoError(err);
        }
    };
    let pre_ino = pre_meta.ino();
    let pre_size = pre_meta.len();

    let computed = match algo {
        HashAlgo::Sha256 => match hash_open_file::<sha2::Sha256>(&mut file) {
            Ok(h) => h,
            Err(err) => {
                metrics::CACHE_IO_FAILURE.increment();
                return Verdict::IoError(err);
            }
        },
        HashAlgo::Sha512 => match hash_open_file::<sha2::Sha512>(&mut file) {
            Ok(h) => h,
            Err(err) => {
                metrics::CACHE_IO_FAILURE.increment();
                return Verdict::IoError(err);
            }
        },
    };

    if computed.as_slice() == expected {
        return Verdict::Match;
    }

    // Race check: a fresh download finishing mid-hash either replaces the
    // file via rename (different inode) or rewrites it in place (size change).
    // Either way our digest is for content no longer at `path`, so bail.
    // Use `symlink_metadata` (lstat): a hostile symlink planted at `path`
    // after the open could otherwise point at a file whose inode/size
    // happen to match `pre_ino` / `pre_size`, masking the race.  lstat
    // compares the symlink itself, so a swap is always detected.
    if let Ok(post_meta) = std::fs::symlink_metadata(path)
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

/// Process one stanza: if its `Filename:` value resolves to a candidate
/// cached file, verify the file content and either retain it (match), warn-
/// and-retain it (no usable hash advertised, transient error, or concurrent
/// rename race), or warn-and-evict it (genuine digest mismatch).
///
/// The `Filename:` field is a full relative path from the repo root.  For
/// structured archives the on-disk cache flattens that to the basename, so
/// the lookup key is the basename portion.  For flat archives the URL path
/// is the on-disk path verbatim, so the lookup key is the relpath itself.
async fn flush_stanza(
    stanza: &mut Stanza,
    file_list: &mut HashMap<String, PathBuf>,
    ctx: &mut ReduceContext<'_>,
) {
    process_stanza(stanza, file_list, ctx).await;
    stanza.reset();
}

/// Body of [`flush_stanza`] split out so a single trailing `stanza.reset()`
/// covers every exit path. Borrows `stanza` immutably; the caller is
/// responsible for clearing it afterwards.
async fn process_stanza(
    stanza: &Stanza,
    file_list: &mut HashMap<String, PathBuf>,
    ctx: &mut ReduceContext<'_>,
) {
    let Some(filename) = stanza.filename.as_deref() else {
        return;
    };

    let lookup_key: &str = if ctx.layout.is_flat() {
        filename
    } else {
        let Some(key) = structured_lookup_key(filename) else {
            return;
        };
        key
    };

    let Some(path) = file_list.get(lookup_key).cloned() else {
        return;
    };

    match stanza.chosen() {
        None => {
            warn!(
                "Packages stanza for `{filename}` advertises no SHA256/SHA512; retaining cache file `{}` without verification",
                path.display(),
            );
            file_list.remove(lookup_key);
        }
        Some((algo, expected)) => {
            // lstat (not stat) so a hostile symlink planted between
            // `collect_cached_files` (which filters via `file_type()`,
            // lstat-semantics) and now is detected here rather than
            // followed.  A non-regular result therefore indicates a
            // concurrent type swap.
            let pre_size = match tokio::fs::symlink_metadata(&path).await {
                Ok(m) if m.file_type().is_file() => m.len(),
                Ok(_) => {
                    metrics::CACHE_NON_REGULAR.increment();
                    warn!(
                        "Cache file `{}` changed to non-regular between cleanup-collect and verify (concurrent swap); retaining without verification",
                        path.display(),
                    );
                    file_list.remove(lookup_key);
                    return;
                }
                Err(err) => {
                    metrics::CACHE_IO_FAILURE.increment();
                    error!(
                        "Failed to stat cache file `{}` before {} verification:  {err}; retaining",
                        path.display(),
                        algo.as_str(),
                    );
                    file_list.remove(lookup_key);
                    return;
                }
            };
            match verify_cache_file(path.clone(), algo, expected.to_vec()).await {
                Verdict::Match => {}
                Verdict::Mismatch { computed } => {
                    warn!(
                        "Cache file `{}` failed {} verification: expected={}, computed={}",
                        path.display(),
                        algo.as_str(),
                        hex_encode(expected),
                        hex_encode(&computed),
                    );
                    if let Err(err) = tokio::fs::remove_file(&path).await {
                        metrics::CACHE_IO_FAILURE.increment();
                        error!(
                            "Error removing checksum-mismatched cache file `{}`:  {err}",
                            path.display()
                        );
                    } else {
                        invalidate_metadata_for(&path, ctx.mirror, ctx.layout);
                        metrics::CLEANUP_CHECKSUM_MISMATCHES.increment();
                        *ctx.mismatch_files += 1;
                        *ctx.mismatch_bytes += pre_size;
                    }
                }
                Verdict::Raced => {
                    warn!(
                        "Cache file `{}` changed during {} verification; retaining (concurrent re-cache)",
                        path.display(),
                        algo.as_str(),
                    );
                }
                Verdict::IoError(err) => {
                    error!(
                        "Failed to {} cache file `{}`:  {err}; retaining",
                        algo.as_str(),
                        path.display(),
                    );
                }
            }
            file_list.remove(lookup_key);
        }
    }
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
        file_list: &mut HashMap<String, PathBuf>,
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

/// Try each of `.xz`, `.gz`, raw in turn — first format that returns 200 wins.
/// Each request is a self-issued `process_cache_request` against `base_uri` +
/// extension; the caller supplies the per-format `debname` and the
/// `CacheLayout` under which to cache the result.
async fn try_fetch_packages_file<F>(
    mirror: &Mirror,
    base_uri: &str,
    layout: CacheLayout,
    debname_for: F,
    appstate: &AppState,
) -> Result<(Response<ProxyCacheBody>, PackageFormat), StatusCode>
where
    F: Fn(PackageFormat) -> String,
{
    let mut uri_buffer = String::with_capacity(base_uri.len() + 3);

    for pkgfmt in [PackageFormat::Xz, PackageFormat::Gz, PackageFormat::Raw] {
        uri_buffer.clear();
        uri_buffer.push_str(base_uri);
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
            debname: debname_for(pkgfmt),
            cached_flavor: CachedFlavor::Volatile,
            layout,
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

/// RAII guard that releases the `task_cleanup` active flag on drop, so a
/// panic inside `task_cleanup_impl` cannot leave the flag stuck `true`
/// (which would block every subsequent scheduled run).
struct ActiveGuard<'a>(&'a parking_lot::Mutex<bool>);

impl Drop for ActiveGuard<'_> {
    fn drop(&mut self) {
        let mut val = self.0.lock();
        debug_assert!(*val, "cleanup state must be active after completion");
        *val = false;
    }
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
    let _guard = ActiveGuard(mutex);

    task_cleanup_impl(appstate).await
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
    //
    // For each mirror, collect the paths of any other mirrors registered
    // under the same alias-resolved (cache_host, port) whose path lives
    // *inside* this mirror's path (segment-aligned).  The flat-cleanup
    // walks the on-disk flat subtree recursively, and these nested mirror
    // roots must be treated as boundaries so a parent mirror's cleanup
    // does not age-evict files that belong to a nested mirror (which has
    // its own Packages index and its own cleanup run).

    // Group mirror paths by (host, port) and sort each group once so each
    // mirror's nested-paths derivation is O(k) over its host's siblings
    // instead of O(n) over every mirror.  Stored as borrows into `mirrors`.
    let mut paths_by_host: HashMap<(&DomainName, u16), Vec<&str>> = HashMap::new();
    for entry in &mirrors {
        paths_by_host
            .entry((&entry.host, entry.port().map_or(0, std::num::NonZero::get)))
            .or_default()
            .push(entry.path.as_str());
    }
    for paths in paths_by_host.values_mut() {
        paths.sort_unstable();
    }

    // Materialise each mirror's nested-paths list to owned data so the
    // `paths_by_host` borrow on `mirrors` can end before we consume
    // `mirrors` in the per-future move below.
    let nested_per_mirror: Vec<Vec<String>> = mirrors
        .iter()
        .map(|mirror| {
            let host_paths = paths_by_host
                .get(&(
                    &mirror.host,
                    mirror.port().map_or(0, std::num::NonZero::get),
                ))
                .map(Vec::as_slice)
                .unwrap_or_default();
            derive_nested_paths(&mirror.path, host_paths)
        })
        .collect();
    drop(paths_by_host);

    let cleanup_tasks = mirrors
        .into_iter()
        .zip(nested_per_mirror)
        .flat_map(|(mirror, nested)| {
            [
                tokio::task::spawn(cleanup_mirror_deb_files(
                    mirror.clone(),
                    appstate.clone(),
                    config,
                )),
                tokio::task::spawn(cleanup_mirror_flat_files(
                    mirror.clone(),
                    nested,
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
        let cleanup_result = match res {
            Ok(Ok(cr)) => cr,
            Ok(Err(err)) => {
                error!("Error in cleanup task:  {err}");
                continue;
            }
            Err(join_err) => {
                error!("Error joining cleanup task:  {join_err}");
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

    match task_cache_scan(&appstate.database).await {
        Ok(actual_cache_size) => {
            let active_downloading_size = appstate.active_downloads.download_size();

            let quota = global_cache_quota();
            let (stored, csize, difference) = quota.subtract_and_reconcile(
                bytes_removed,
                actual_cache_size,
                active_downloading_size,
            );

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
        Err(err) => {
            error!("Skipping cache-size reconciliation after cleanup:  {err}");
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

impl CleanupDone {
    fn empty(mirror: Mirror) -> Self {
        Self::tally(mirror, 0, 0, 0)
    }

    fn retained_only(mirror: Mirror, retained: u64) -> Self {
        Self {
            mirror,
            files_retained: retained,
            files_removed: 0,
            bytes_removed: 0,
        }
    }

    fn tally(mirror: Mirror, total: u64, files_removed: u64, bytes_removed: u64) -> Self {
        Self {
            mirror,
            files_retained: total.saturating_sub(files_removed),
            files_removed,
            bytes_removed,
        }
    }
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
        return Ok(CleanupDone::retained_only(mirror, num_total_files));
    }

    let mut mismatch_files: u64 = 0;
    let mut mismatch_bytes: u64 = 0;

    for origin in &active_origins {
        let base_uri = origin.uri();
        let (mut response, pkgfmt) = match try_fetch_packages_file(
            &mirror,
            &base_uri,
            CacheLayout::Dists,
            |pkgfmt| {
                format!(
                    "{}_{}_{}_Packages{}",
                    origin.distribution,
                    origin.component,
                    origin.architecture,
                    pkgfmt.extension()
                )
            },
            &appstate,
        )
        .await
        {
            // A missing Packages file leaves us unable to complete the
            // reference set; deleting now risks wiping files referenced
            // only by this origin (typical when a distribution goes EOL
            // upstream). Bail conservatively and retry next cycle.
            Err(status) => {
                warn!(
                    "Could not fetch package file for {origin:?} ({status}); skipping cleanup for mirror {mirror}"
                );

                return Ok(CleanupDone::tally(
                    mirror,
                    num_total_files,
                    mismatch_files,
                    mismatch_bytes,
                ));
            }
            Ok(r) => r,
        };

        let memfdname = format!(
            "{}_{}_{}_packages{}",
            origin.distribution,
            origin.component,
            origin.architecture,
            pkgfmt.extension(),
        );

        let file = packages_body_to_memfd(&memfdname, response.body_mut(), config).await?;

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
            return Ok(CleanupDone::tally(
                mirror,
                num_total_files,
                mismatch_files,
                mismatch_bytes,
            ));
        }
    }

    // Files left in `cached_files` are not referenced by any Packages
    // stanza we fetched.  They may legitimately belong to an origin not
    // yet observed by the proxy (e.g. `apt update` run un-proxied), so a
    // grace period of `UNREFERENCED_KEEP_SPAN` keeps young files in place;
    // older unreferenced files are reaped.
    let (aged_files, aged_bytes) = sweep_aged_cached_debs(
        &cached_files,
        UNREFERENCED_KEEP_SPAN,
        &mirror,
        CacheLayout::StructuredPool,
    )
    .await;

    info!(
        "Removed {aged_files} unreferenced deb files for mirror {mirror} ({})",
        HumanFmt::Size(aged_bytes)
    );

    Ok(CleanupDone::tally(
        mirror,
        num_total_files,
        mismatch_files + aged_files,
        mismatch_bytes + aged_bytes,
    ))
}

/// Derive the paths of mirrors registered under the same `(host, port)` that
/// live *inside* `mirror_path` (segment-aligned), given the sorted list of
/// sibling paths on that host (which may include `mirror_path` itself; self
/// is filtered out by the segment-alignment check).
///
/// The empty-`mirror_path` case denotes a host-root mirror that nests every
/// other path on the host.
///
/// Sorted input lets the lookup skip directly to the prefix region via
/// `partition_point`.  Within that region, lexicographic order can still
/// interleave non-nested neighbours (e.g. `debian-security` between `debian`
/// and `debian/...` since `-` < `/` in ASCII), so segment alignment is
/// enforced as a filter rather than a `take_while` terminator.
#[must_use]
fn derive_nested_paths(mirror_path: &str, host_paths_sorted: &[&str]) -> Vec<String> {
    if mirror_path.is_empty() {
        return host_paths_sorted
            .iter()
            .filter(|p| !p.is_empty())
            .map(|p| (*p).to_owned())
            .collect();
    }
    let start = host_paths_sorted.partition_point(|p| *p <= mirror_path);
    host_paths_sorted[start..]
        .iter()
        .take_while(|p| p.starts_with(mirror_path))
        .filter(|p| is_strict_path_descendant(p, mirror_path))
        .map(|p| (*p).to_owned())
        .collect()
}

/// Whether the on-disk position `candidate` (the mirror-path-equivalent of
/// a subdir reached during recursion) sits at or inside a registered nested
/// mirror's root.  Match semantics are segment-aligned:
///
/// - `apt/amd64` matches the registered root `apt/amd64` (equality).
/// - `apt/amd64/foo` matches the registered root `apt/amd64` (descendant —
///   the walker has already entered the nested subtree).
/// - `apt/amd64` does **not** match the registered root `apt/amd64/special`:
///   recursion must continue into `apt/amd64` so the walker can reach the
///   real boundary at `apt/amd64/special`.
/// - `apt-tools` does not match the registered root `apt` (segment-aligned,
///   not a byte prefix).
#[must_use]
fn is_nested_mirror_boundary(candidate: &str, nested_mirror_paths: &[String]) -> bool {
    nested_mirror_paths
        .iter()
        .any(|p| path_starts_with_segment(candidate, p))
}

/// Collect Debian binary packages (`.deb`, `.udeb`, `.ddeb`) under a flat
/// repository root, recursing into any sub-directories.  Keys are paths
/// relative to `flat_root`, forward-slash joined to match the `Filename:`
/// stanza syntax.  Metadata files, the `by-hash/` subtree, the `tmp/`
/// partial-download dir, and symlinks are skipped.
///
/// `mirror_path` is the path of the mirror being cleaned (e.g. `apt`);
/// `nested_mirror_paths` lists paths of other registered mirrors under the
/// same host that live *inside* `mirror_path` (e.g. `apt/amd64`).  When the
/// recursion reaches a directory that is itself the root of (or contains) a
/// nested mirror, the subtree is skipped — that mirror has its own Packages
/// index and its own cleanup run, so the parent must not own those files.
async fn collect_flat_cached_debs(
    flat_root: &Path,
    mirror_path: &str,
    nested_mirror_paths: &[String],
) -> Result<HashMap<String, PathBuf>, ProxyCacheError> {
    let mut ret = HashMap::new();
    let mut stack: Vec<(PathBuf, String)> = vec![(flat_root.to_path_buf(), String::new())];

    while let Some((current, rel_prefix)) = stack.pop() {
        let mut dir = match tokio::fs::read_dir(&current).await {
            Ok(d) => d,
            Err(err) if err.kind() == ErrorKind::NotFound => continue,
            Err(err) => {
                metrics::CACHE_IO_FAILURE.increment();
                error!("Failed to read directory `{}`:  {err}", current.display());
                return Err(ProxyCacheError::Io(err));
            }
        };

        loop {
            let entry = match dir.next_entry().await {
                Ok(Some(e)) => e,
                Ok(None) => break,
                Err(err) => {
                    metrics::CACHE_IO_FAILURE.increment();
                    error!(
                        "Failed to iterate directory `{}`:  {err}",
                        current.display()
                    );
                    return Err(ProxyCacheError::Io(err));
                }
            };
            let name = entry.file_name();
            let Some(name_str) = name.to_str() else {
                warn!("Skipping unrecognized entry `{}`", entry.path().display());
                continue;
            };

            // Use `file_type()` (lstat semantics) so a symlink planted in
            // the cache by a hostile filesystem doesn't trick us into
            // walking outside the cache tree.
            let file_type = match entry.file_type().await {
                Ok(ft) => ft,
                Err(err) => {
                    metrics::CACHE_IO_FAILURE.increment();
                    error!(
                        "Failed to get file type of `{}`:  {err}",
                        entry.path().display()
                    );
                    continue;
                }
            };

            if file_type.is_symlink() {
                metrics::CACHE_NON_REGULAR.increment();
                let path = entry.path();
                warn!(
                    "Removing unrecognized symlink entry in cache: `{}`",
                    path.display()
                );
                if let Err(err) = tokio::fs::remove_file(&path).await {
                    metrics::CACHE_IO_FAILURE.increment();
                    error!(
                        "Failed to remove symlink entry `{}`:  {err}",
                        path.display()
                    );
                } else {
                    debug!("Removed symlink entry `{}`", path.display());
                }
                continue;
            }

            if file_type.is_dir() {
                // Skip the by-hash subtree (handled by the by-hash
                // cleanup), the tmp partial-download dir, and recurse
                // everything else.
                if name == SUBDIR_FLAT_BYHASH || name == SUBDIR_TMP {
                    continue;
                }
                let child_rel = if rel_prefix.is_empty() {
                    name_str.to_owned()
                } else {
                    format!("{rel_prefix}/{name_str}")
                };

                // Translate the on-disk position back to a mirror-path
                // equivalent (`<mirror_path>/<child_rel>`) so it can be
                // compared against the registered nested mirror paths.
                // Hits delimit a boundary: the nested mirror owns
                // everything inside, so do not descend.
                let owned_full;
                let candidate_full: &str = if mirror_path.is_empty() {
                    child_rel.as_str()
                } else {
                    owned_full = format!("{mirror_path}/{child_rel}");
                    owned_full.as_str()
                };
                if is_nested_mirror_boundary(candidate_full, nested_mirror_paths) {
                    trace!(
                        "Skipping `{}` during flat cleanup: nested mirror root for `{candidate_full}`",
                        entry.path().display(),
                    );
                    continue;
                }

                stack.push((entry.path(), child_rel));
                continue;
            }

            if !file_type.is_file() {
                metrics::CACHE_NON_REGULAR.increment();
                let path = entry.path();
                warn!("Removing non-regular entry in cache: `{}`", path.display());
                if let Err(err) = tokio::fs::remove_file(&path).await {
                    metrics::CACHE_IO_FAILURE.increment();
                    error!(
                        "Failed to remove non-regular entry `{}`:  {err}",
                        path.display()
                    );
                } else {
                    debug!("Removed non-regular entry `{}`", path.display());
                }
                continue;
            }

            if !is_deb_package(name_str) {
                continue;
            }

            let key = if rel_prefix.is_empty() {
                name_str.to_owned()
            } else {
                format!("{rel_prefix}/{name_str}")
            };
            ret.insert(key, entry.path());
        }
    }

    Ok(ret)
}

/// Remove cached deb files in `cached_files` that are older than `keep_span`,
/// dropping any matching `cache_metadata` entries on success.
///
/// Used by the flat-cleanup path both when a Packages index has reduced the
/// map down to genuinely-unreferenced files (short span) and as a fallback
/// when the Packages index is unfetchable (long span, since we cannot tell
/// which entries are still referenced).
async fn sweep_aged_cached_debs(
    cached_files: &HashMap<String, PathBuf>,
    keep_span: Duration,
    mirror: &Mirror,
    layout: CacheLayout,
) -> (u64, u64) {
    let mut bytes_removed = 0u64;
    let mut files_removed = 0u64;
    let now = SystemTime::now();

    for path in cached_files.values() {
        let data = match tokio::fs::symlink_metadata(path).await {
            Ok(d) if d.file_type().is_file() => Some(d),
            Ok(_) => {
                metrics::CACHE_NON_REGULAR.increment();
                warn!(
                    "Cache file `{}` is not a regular file; retaining",
                    path.display(),
                );
                None
            }
            Err(err) => {
                metrics::CACHE_IO_FAILURE.increment();
                error!(
                    "Error inspecting cached file `{}`:  {err}; retaining",
                    path.display()
                );
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
                            metrics::CACHE_IO_FAILURE.increment();
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

        let size = data.as_ref().map_or(0, std::fs::Metadata::len);

        if let Err(err) = tokio::fs::remove_file(&path).await {
            metrics::CACHE_IO_FAILURE.increment();
            error!("Error removing cached file `{}`:  {err}", path.display());
            continue;
        }

        invalidate_metadata_for(path, mirror, layout);

        debug!("Removed cached file `{}`", path.display());

        bytes_removed += size;
        files_removed += 1;
    }

    (files_removed, bytes_removed)
}

async fn cleanup_mirror_flat_files(
    mirror: MirrorEntry,
    nested_mirror_paths: Vec<String>,
    appstate: AppState,
    config: &Config,
) -> Result<CleanupDone, ProxyCacheError> {
    // Under the host-anchored flat layout, a mirror's flat root lives at
    // `<cache>/<host>/flat/<mirror_path>/` — sibling of the host-level
    // structured tree at `<cache>/<host>/<mirror_path>/`.  `flat_root_path`
    // resolves the alias-main host, matching `ConnectionDetails::cache_dir_path`.
    let flat_path = mirror.flat_root_path(&config.cache_directory);

    // Probe: skip mirrors that have no flat subtree.  Most `mirrors_v2`
    // rows are structured-only; touching them every cleanup cycle would
    // be wasted work.  Only mirrors that have served at least one flat
    // resource have a `<host>/flat/<mirror_path>/` dir on disk.
    match probe_dir(&flat_path, "flat cleanup").await {
        Ok(true) => {}
        Ok(false) => {
            return Ok(CleanupDone::empty(mirror.into()));
        }
        Err(err) => {
            metrics::CACHE_IO_FAILURE.increment();
            error!(
                "Error probing flat directory `{}`:  {err}",
                flat_path.display()
            );
            return Err(ProxyCacheError::Io(err));
        }
    }

    let mut cached_files = collect_flat_cached_debs(&flat_path, &mirror.path, &nested_mirror_paths)
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
        return Ok(CleanupDone::retained_only(mirror, num_total_files));
    }

    let base_uri = format!(
        "http://{}/{}/Packages",
        mirror.format_authority(),
        mirror.path()
    );
    let (mut response, pkgfmt) = match try_fetch_packages_file(
        &mirror,
        &base_uri,
        CacheLayout::Flat,
        |pkgfmt| format!("Packages{}", pkgfmt.extension()),
        &appstate,
    )
    .await
    {
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
            return Ok(CleanupDone::tally(
                mirror,
                num_total_files,
                files_removed,
                bytes_removed,
            ));
        }
    };

    let memfdname = format!("flat_packages{}", pkgfmt.extension());

    let file = packages_body_to_memfd(&memfdname, response.body_mut(), config).await?;

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
        return Ok(CleanupDone::tally(
            mirror,
            num_total_files,
            mismatch_files,
            mismatch_bytes,
        ));
    }

    let (aged_files, aged_bytes) = sweep_aged_cached_debs(
        &cached_files,
        UNREFERENCED_KEEP_SPAN,
        &mirror,
        CacheLayout::Flat,
    )
    .await;

    info!(
        "Removed {aged_files} unreferenced flat deb files for mirror {mirror} ({})",
        HumanFmt::Size(aged_bytes)
    );

    Ok(CleanupDone::tally(
        mirror,
        num_total_files,
        mismatch_files + aged_files,
        mismatch_bytes + aged_bytes,
    ))
}

/// Result of a single by-hash directory walk.
#[derive(Default)]
struct ByHashStats {
    files_retained: u64,
    files_removed: u64,
    bytes_removed: u64,
}

impl ByHashStats {
    #[expect(
        clippy::needless_pass_by_value,
        reason = "other is not needed after accumulation"
    )]
    fn accumulate(&mut self, other: Self) {
        self.files_retained += other.files_retained;
        self.files_removed += other.files_removed;
        self.bytes_removed += other.bytes_removed;
    }
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

    // No upfront `probe_dir`: `read_dir` returns NotFound when the per-
    // layout by-hash root is absent (the common case for structured-only
    // or flat-only mirrors), so the cheap path is one syscall.  Symlink
    // hardening is performed per-entry inside the loop, which already
    // uses `file_type()` (lstat semantics); the only difference would be
    // a symlinked *root*, which is one directory shallower than where an
    // attacker could plant anything useful given the cache tree's
    // invariants (mirror_path is validated and the parent dirs are
    // created by the daemon).
    let mut byhash_dir = match tokio::fs::read_dir(byhash_path).await {
        Ok(d) => d,
        Err(err) if err.kind() == ErrorKind::NotFound => return Ok(stats),
        Err(err) => {
            metrics::CACHE_IO_FAILURE.increment();
            error!(
                "Failed to read directory `{}`:  {}",
                byhash_path.display(),
                err
            );
            return Err(ProxyCacheError::Io(err));
        }
    };

    loop {
        let entry = match byhash_dir.next_entry().await {
            Ok(Some(e)) => e,
            Ok(None) => break,
            Err(err) => {
                metrics::CACHE_IO_FAILURE.increment();
                error!(
                    "Failed to iterate directory `{}`:  {err}",
                    byhash_path.display()
                );
                return Err(ProxyCacheError::Io(err));
            }
        };
        let path = entry.path();

        let (mdata, file_type) = match entry.metadata().await {
            Ok(d) => {
                let ft = d.file_type();
                (d, ft)
            }
            Err(err) => {
                metrics::CACHE_IO_FAILURE.increment();
                error!("Error inspecting file `{}`:  {err}", path.display());
                continue;
            }
        };

        if !file_type.is_file() {
            metrics::CACHE_NON_REGULAR.increment();
            if file_type.is_dir() {
                warn!(
                    "Skipping unexpected directory in by-hash directory: `{}`",
                    path.display()
                );
            } else {
                warn!(
                    "Removing non-regular entry in by-hash directory: `{}`",
                    path.display()
                );
                if let Err(err) = tokio::fs::remove_file(&path).await {
                    metrics::CACHE_IO_FAILURE.increment();
                    error!(
                        "Failed to remove non-regular entry `{}`:  {err}",
                        path.display()
                    );
                } else {
                    debug!("Removed non-regular entry `{}`", path.display());
                    stats.bytes_removed += mdata.len();
                    stats.files_removed += 1;
                }
            }
            continue;
        }

        stats.files_retained += 1;

        let modified = match mdata.modified() {
            Ok(m) => m,
            Err(err) => {
                metrics::CACHE_IO_FAILURE.increment();
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
            metrics::CACHE_IO_FAILURE.increment();
            error!("Error removing file `{}`:  {err}", path.display());
            continue;
        }

        invalidate_metadata_for(&path, mirror, layout);

        stats.bytes_removed += mdata.len();
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

    // Build both by-hash paths up front so the subsequent `mirror.into()`
    // move can hand the owned `Mirror` to `cleanup_byhash_dir` without
    // forcing extra owned-copy/clone of derived path data.
    let dists_byhash: PathBuf = [
        config.cache_directory.as_path(),
        mirror.cache_path().as_path(),
        Path::new(SUBDIR_DISTS_BYHASH),
    ]
    .iter()
    .collect();
    let flat_byhash = mirror
        .flat_root_path(&config.cache_directory)
        .join(SUBDIR_FLAT_BYHASH);
    let mirror: Mirror = mirror.into();

    let mut total = ByHashStats::default();

    // Walk the structured (`<host>/<mirror>/dists/by-hash/`) by-hash tree.
    total.accumulate(
        cleanup_byhash_dir(
            &dists_byhash,
            keep_span,
            now,
            &mirror,
            CacheLayout::DistsByHash,
        )
        .await?,
    );

    // Walk the flat (`<host>/flat/<mirror_path>/by-hash/`) by-hash tree.
    total.accumulate(
        cleanup_byhash_dir(
            &flat_byhash,
            keep_span,
            now,
            &mirror,
            CacheLayout::FlatByHash,
        )
        .await?,
    );

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
/// policy.  Both layout branches are probed — structured at
/// `<cache>/<host>/<mirror_path>/tmp/` and flat at
/// `<cache>/<host>/flat/<mirror_path>/tmp/` — unconditionally rather than
/// gated on the row's `kind` column: that column latches to `Structured`
/// once any structured request arrives for a row, so a `kind = Structured`
/// row can still own legacy flat partials from before the collision was
/// seen.
/// Each branch short-circuits on `NotFound`, so the wasted-stat cost on
/// single-shape mirrors is one syscall per cleanup cycle.
async fn cleanup_stale_partials(cache_dir: &Path, mirrors: &[MirrorEntry]) {
    let now = SystemTime::now();
    let mut removed = 0u64;

    for mirror in mirrors {
        let mirror_dir = mirror_cache_path_impl(mirror.cache_host(), mirror.port(), &mirror.path);
        let structured_tmp: PathBuf = [cache_dir, mirror_dir.as_path(), Path::new(SUBDIR_TMP)]
            .iter()
            .collect();
        removed += cleanup_tmp_dir(&structured_tmp, now).await;

        let flat_tmp = mirror.flat_root_path(cache_dir).join(SUBDIR_TMP);
        removed += cleanup_tmp_dir(&flat_tmp, now).await;
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
            metrics::CACHE_IO_FAILURE.increment();
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
                metrics::CACHE_IO_FAILURE.increment();
                error!(
                    "Failed to iterate tmp directory `{}`:  {err}",
                    tmp_dir.display()
                );
                break;
            }
        };

        let (mdata, file_type) = match entry.metadata().await {
            Ok(m) => {
                let ft = m.file_type();
                (m, ft)
            }
            Err(err) => {
                metrics::CACHE_IO_FAILURE.increment();
                error!(
                    "Failed to stat tmp entry `{}`:  {err}",
                    entry.path().display()
                );
                continue;
            }
        };

        let mtime = mdata.modified().unwrap_or(SystemTime::UNIX_EPOCH);
        // Apply the per-suffix `.partial` policy only to regular files: a
        // symlink-to-dir or a stray directory named `*.partial` should not
        // be measured by `len()` (zero for a symlink) and should be reaped
        // under the longer foreign cutoff instead.
        let is_partial = file_type.is_file()
            && entry
                .file_name()
                .to_str()
                .is_some_and(|name| name.ends_with(".partial"));
        let should_remove = if is_partial {
            // Zero-byte partials carry no resume state; aged partials are stale.
            mdata.len() == 0 || mtime < partial_cutoff
        } else if mtime < foreign_cutoff {
            true
        } else {
            debug!(
                "Keeping unexpected tmp entry `{}` (not yet past foreign cutoff)",
                entry.path().display()
            );
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
                metrics::CACHE_NON_REGULAR.increment();
                warn!("Removing directory tmp entry `{}`", entry.path().display());
                tokio::fs::remove_dir_all(&path).await
            } else if !file_type.is_file() {
                metrics::CACHE_NON_REGULAR.increment();
                warn!(
                    "Removing non-regular tmp entry `{}`",
                    entry.path().display()
                );
                tokio::fs::remove_file(&path).await
            } else {
                tokio::fs::remove_file(&path).await
            };
            if let Err(err) = removal {
                metrics::CACHE_IO_FAILURE.increment();
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

    fn sorted(paths: &[&'static str]) -> Vec<&'static str> {
        let mut v = paths.to_vec();
        v.sort_unstable();
        v
    }

    #[test]
    fn derive_nested_paths_basic_nesting() {
        let host = sorted(&["debian", "debian/security", "debian/x/y", "unrelated"]);
        assert_eq!(
            derive_nested_paths("debian", &host),
            vec!["debian/security".to_owned(), "debian/x/y".to_owned()]
        );
    }

    #[test]
    fn derive_nested_paths_skips_non_segment_aligned_prefix_neighbour() {
        // `debian-security` sorts between `debian` and `debian/...` (`-` < `/`)
        // but is not a nested child; the segment-alignment filter must keep
        // the take_while running past it instead of stopping early.
        let host = sorted(&["debian", "debian-security", "debian/foo", "debian/security"]);
        assert_eq!(
            derive_nested_paths("debian", &host),
            vec!["debian/foo".to_owned(), "debian/security".to_owned()]
        );
    }

    #[test]
    fn derive_nested_paths_empty_mirror_path_nests_all_others() {
        let host = sorted(&["", "debian", "debian/security"]);
        assert_eq!(
            derive_nested_paths("", &host),
            vec!["debian".to_owned(), "debian/security".to_owned()]
        );
    }

    #[test]
    fn derive_nested_paths_excludes_self() {
        let host = sorted(&["debian"]);
        assert!(derive_nested_paths("debian", &host).is_empty());
    }

    #[test]
    fn derive_nested_paths_no_match() {
        let host = sorted(&["apt", "debian"]);
        assert!(derive_nested_paths("ubuntu", &host).is_empty());
    }

    #[test]
    fn is_nested_mirror_boundary_equality_match() {
        let nested = vec!["apt/amd64".to_owned()];
        assert!(is_nested_mirror_boundary("apt/amd64", &nested));
    }

    #[test]
    fn is_nested_mirror_boundary_descendant_inside_nested_subtree() {
        let nested = vec!["apt/amd64".to_owned()];
        assert!(is_nested_mirror_boundary("apt/amd64/foo", &nested));
    }

    #[test]
    fn is_nested_mirror_boundary_ancestor_must_recurse() {
        // Regression guard against the reversed-argument bug: a candidate
        // that is a strict ancestor of a registered nested root is NOT a
        // boundary — the walker has to continue down to reach the real
        // nested root.
        let nested = vec!["apt/amd64/special".to_owned()];
        assert!(!is_nested_mirror_boundary("apt/amd64", &nested));
    }

    #[test]
    fn is_nested_mirror_boundary_segment_aligned_non_match() {
        let nested = vec!["apt".to_owned()];
        assert!(!is_nested_mirror_boundary("apt-tools", &nested));
    }

    #[test]
    fn parse_filename_field_strips_lf() {
        assert_eq!(
            parse_filename_field("Filename: pool/main/a/abc/abc_1.0_amd64.deb\n"),
            Some("pool/main/a/abc/abc_1.0_amd64.deb"),
        );
    }

    #[test]
    fn parse_filename_field_strips_crlf() {
        assert_eq!(
            parse_filename_field("Filename: pool/main/a/abc/abc_1.0_amd64.deb\r\n"),
            Some("pool/main/a/abc/abc_1.0_amd64.deb"),
        );
    }

    #[test]
    fn parse_filename_field_no_terminator() {
        assert_eq!(
            parse_filename_field("Filename: pool/main/a/abc/abc_1.0_amd64.deb"),
            Some("pool/main/a/abc/abc_1.0_amd64.deb"),
        );
    }

    #[test]
    fn parse_filename_field_handles_udeb_extension() {
        assert_eq!(
            parse_filename_field("Filename: pool/main/i/inst/inst_1.0_amd64.udeb\n"),
            Some("pool/main/i/inst/inst_1.0_amd64.udeb"),
        );
    }

    #[test]
    fn parse_filename_field_returns_nested_relpath_for_flat() {
        // Flat repos cite paths relative to the repo root; cleanup needs
        // to disambiguate same-basename debs across sub-directories.
        assert_eq!(
            parse_filename_field("Filename: amd64/twilio-cli_5.0.0_amd64.deb\n"),
            Some("amd64/twilio-cli_5.0.0_amd64.deb"),
        );
    }

    #[test]
    fn parse_filename_field_skips_other_keys() {
        assert_eq!(parse_filename_field("Package: stub\n"), None);
        assert_eq!(parse_filename_field("\n"), None);
        assert_eq!(parse_filename_field(""), None);
    }

    #[test]
    fn parse_filename_field_rejects_traversal() {
        // Path-traversal hardening: an attacker-controlled upstream
        // Packages stanza must not be able to inject `..` segments or
        // absolute paths that could later be joined to a filesystem path.
        assert_eq!(
            parse_filename_field("Filename: ../../../etc/passwd\n"),
            None,
        );
        assert_eq!(parse_filename_field("Filename: pool/../escape.deb\n"), None);
        assert_eq!(parse_filename_field("Filename: /etc/shadow\n"), None);
        assert_eq!(parse_filename_field("Filename: ./foo.deb\n"), None);
        assert_eq!(parse_filename_field("Filename: a//b.deb\n"), None);
        assert_eq!(
            parse_filename_field("Filename: pool\\main\\evil.deb\n"),
            None,
        );
        // NUL byte rejection — Rust strings allow `\0`; rust source uses
        // an explicit escape to materialise the test input.
        assert_eq!(parse_filename_field("Filename: pool/x\0y.deb\n"), None,);
        // Other ASCII control characters (tab, vertical tab, bare CR/LF
        // embedded mid-segment, etc.) are likewise rejected so they can
        // never reach a downstream HashMap lookup or future filesystem
        // join.
        assert_eq!(parse_filename_field("Filename: pool/x\ty.deb\n"), None);
        assert_eq!(parse_filename_field("Filename: pool/x\x0by.deb\n"), None);
        assert_eq!(parse_filename_field("Filename: pool/x\x7fy.deb\n"), None);
    }

    #[test]
    fn structured_lookup_key_extracts_basename() {
        assert_eq!(
            structured_lookup_key("pool/main/a/abc/abc_1.0_amd64.deb"),
            Some("abc_1.0_amd64.deb"),
        );
        assert_eq!(
            structured_lookup_key("abc_1.0_amd64.deb"),
            Some("abc_1.0_amd64.deb"),
        );
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
        assert_eq!(
            s.filename.as_deref(),
            Some("pool/main/a/abc/abc_1.0_amd64.deb"),
        );
        assert_eq!(s.chosen(), Some((HashAlgo::Sha256, [0xab; 32].as_slice())));
    }

    #[test]
    fn stanza_chosen_prefers_sha256_over_sha512() {
        let mut s = Stanza::new();
        s.sha256 = Some([0x11u8; 32]);
        s.sha512 = Some([0x22u8; 64]);
        assert_eq!(
            s.chosen(),
            Some((HashAlgo::Sha256, [0x11u8; 32].as_slice()))
        );
    }

    #[test]
    fn stanza_chosen_falls_back_to_sha512() {
        let mut s = Stanza::new();
        s.sha512 = Some([0x33u8; 64]);
        assert_eq!(
            s.chosen(),
            Some((HashAlgo::Sha512, [0x33u8; 64].as_slice()))
        );
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
