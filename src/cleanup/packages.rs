use std::borrow::Cow;
use std::num::NonZero;

use bytes::Buf as _;
use hashbrown::HashMap;
use http::{Method, Request, Response, StatusCode, header::CACHE_CONTROL};
use http_body_util::{BodyExt as _, Empty};
use memfd::MemfdOptions;
use tokio::io::{AsyncBufRead, AsyncSeekExt as _, AsyncWriteExt as _, BufWriter};
use tracing::{debug, error, warn};

use crate::{
    AppState, ClientInfo, Never, ProxyCacheBody,
    cache_layout::{CacheLayout, CachedFlavor, ConnectionDetails, ResourceKind},
    config::Config,
    deb_mirror::Mirror,
    error::{ProxyCacheError, UpstreamFetchError},
    hyper_conn::process_cache_request,
    index_parser::{Stanza, hex_encode, structured_lookup_key},
    limits::{
        CappedLine, LimitedReader, MAX_DECOMPRESSED_PACKAGES_SIZE, MAX_DECOMPRESSION_RATIO,
        MAX_METADATA_LINE_LEN, read_line_capped,
    },
    metrics,
    precise_instant::PreciseInstant,
    xz_stream::xz_decoder,
};

use super::engine::Candidate;
use super::invalidate_metadata_for;
use super::verify::{Verdict, verify_cache_file};

/// How a `Filename:` value from a Packages stanza maps to a key in the
/// scanned candidate map. Replaces the old `flat_lookup_prefix` string +
/// `layout.is_flat()` branch in `process_stanza`.
pub(super) enum KeyMapper<'a> {
    /// Structured pool: the cache flattens to basename.
    Basename,
    /// Flat repo, Packages co-located with the mirror root: key = relpath.
    Relpath,
    /// Flat repo, Packages fetched from an ancestor: `Filename:` values are
    /// relative to that ancestor. Keep only entries under `prefix` (which
    /// carries a trailing `/`); strip it. Entries outside the subtree map to
    /// `None` (they belong to a sibling).
    RelpathUnderPrefix { prefix: &'a str },
}

impl KeyMapper<'_> {
    pub(super) fn map<'a>(&self, filename: &'a str) -> Option<Cow<'a, str>> {
        match self {
            Self::Basename => structured_lookup_key(filename).map(Cow::Borrowed),
            Self::Relpath => Some(Cow::Borrowed(filename)),
            Self::RelpathUnderPrefix { prefix } => filename.strip_prefix(prefix).map(Cow::Borrowed),
        }
    }
}

/// Buffer `body` into `file`, returning the file (rewound to offset 0) and the
/// number of bytes written. The caller compares the byte count against the
/// upstream-announced `Content-Length` to detect a silently-truncated body (a
/// download aborted mid-stream closes the delivery channel with a clean EOF, so
/// the short read surfaces here as `Ok`, not `Err`).
///
/// `max_bytes` bounds how much is buffered before the (post-hoc) decompression
/// guards in `reduce_file_list` can weigh in: an abusive upstream could
/// otherwise stream an unbounded compressed (or raw) body straight into memory.
/// Exceeding it returns `Err` rather than truncating -- a short buffer would
/// silently shrink the reference set and over-evict -- which the caller maps to
/// a conservative fetch failure. The check is per-chunk, so at most one extra
/// buffer is held transiently over the cap.
async fn body_to_file(
    body: &mut ProxyCacheBody,
    file: tokio::fs::File,
    max_bytes: NonZero<u64>,
    config: &Config,
) -> Result<(tokio::fs::File, u64), ProxyCacheError> {
    let mut writer = BufWriter::with_capacity(config.buffer_size, file);

    let mut written: u64 = 0;
    while let Some(next) = body.frame().await {
        let frame = next.map_err(|err| *err)?;
        if let Ok(mut chunk) = frame.into_data() {
            written = written.saturating_add(chunk.remaining() as u64);
            if written > max_bytes.get() {
                return Err(ProxyCacheError::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "compressed Packages exceeds size cap",
                )));
            }
            writer.write_all_buf(&mut chunk).await?;
        }
    }

    writer.flush().await?;

    let mut file = writer.into_inner();

    file.rewind().await?;

    Ok((file, written))
}

/// `true` only when the upstream announced an exact `Content-Length` and we
/// buffered fewer bytes -- a clean-EOF truncation (e.g. an aborted upstream
/// download). `None` (chunked / volatile-unknown / legitimately empty) is never
/// "incomplete".
#[must_use]
pub(super) fn body_is_incomplete(announced: Option<u64>, written: u64) -> bool {
    matches!(announced, Some(expected) if written < expected)
}

pub(super) async fn packages_body_to_memfd(
    memfdname: &str,
    body: &mut ProxyCacheBody,
    config: &Config,
) -> Result<(tokio::fs::File, u64), ProxyCacheError> {
    let memfd = MemfdOptions::new().create(memfdname).map_err(|err| {
        error!("Error creating in-memory file `{memfdname}`:  {err}");
        ProxyCacheError::Memfd(err)
    })?;
    let file = tokio::fs::File::from_std(memfd.into_file());
    // Cap the buffered body at the decompressed ceiling: a compressed index can
    // never legitimately exceed its own decompressed size, so this rejects
    // nothing real while bounding memory before `reduce_file_list`'s guards run.
    body_to_file(body, file, MAX_DECOMPRESSED_PACKAGES_SIZE, config)
        .await
        .inspect_err(|err| {
            error!("Failed to write response to in-memory file `{memfdname}`:  {err}");
        })
}

/// Per-call context for [`PackageFormat::reduce_file_list`]: needed to invalidate
/// per-file `cache_metadata` entries and to attribute checksum-mismatch
/// removals back to the per-mirror `CleanupDone` totals.
pub(super) struct ReduceContext<'a> {
    pub(super) mirror: &'a Mirror,
    pub(super) layout: CacheLayout,
    pub(super) mismatch_files: &'a mut u64,
    pub(super) mismatch_bytes: &'a mut u64,
    /// Derives the lookup key from a `Filename:` relpath. Replaces the old
    /// `flat_lookup_prefix` + `layout.is_flat()` branch.
    pub(super) keymap: &'a KeyMapper<'a>,
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
    file_list: &mut HashMap<String, Candidate>,
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
    file_list: &mut HashMap<String, Candidate>,
    ctx: &mut ReduceContext<'_>,
) {
    let Some(filename) = stanza.filename.as_deref() else {
        return;
    };

    let Some(lookup_key) = ctx.keymap.map(filename) else {
        return;
    };
    let lookup_key: &str = &lookup_key;

    let Some(path) = file_list
        .get(lookup_key)
        .map(|candidate| candidate.path.clone())
    else {
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
            // `scan_candidates` (which filters via `file_type()`,
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

/// Compute the effective decompressed-output ceiling for a `Packages` file of
/// `compressed_size` bytes: the smaller of the absolute cap and the
/// compression-ratio cap.
#[must_use]
fn decompressed_limit(compressed_size: NonZero<u64>) -> NonZero<u64> {
    MAX_DECOMPRESSED_PACKAGES_SIZE.min(compressed_size.saturating_mul(MAX_DECOMPRESSION_RATIO))
}

#[derive(Clone, Copy)]
pub(super) enum PackageFormat {
    Raw,
    Gz,
    Xz,
}

impl PackageFormat {
    #[must_use]
    pub(super) const fn extension(self) -> &'static str {
        match self {
            Self::Raw => "",
            Self::Gz => ".gz",
            Self::Xz => ".xz",
        }
    }

    /// Stream a (possibly compressed) Debian `Packages` file stanza by stanza,
    /// reducing the candidate `file_list` by basename and verifying matched
    /// cache files against the stanza's `SHA256:`/`SHA512:` digest.
    pub(super) async fn reduce_file_list(
        self,
        file: tokio::fs::File,
        filename: &str,
        file_list: &mut HashMap<String, Candidate>,
        ctx: &mut ReduceContext<'_>,
        config: &Config,
    ) -> Result<(), ProxyCacheError> {
        debug_assert!(!file_list.is_empty(), "avoid unnecessary work");

        let buffer_size = config.buffer_size;

        let mdata = match file.metadata().await {
            Ok(m) => m,
            Err(err) => {
                error!(
                    "Failed to stat Packages file `{filename}` for decompression-ratio guard:  {err}"
                );
                return Err(ProxyCacheError::Io(err));
            }
        };

        let Some(compressed_size) = NonZero::new(mdata.len()) else {
            return match self {
                // A raw Packages file with zero stanzas is legal (e.g.
                // a freshly-created component with no published debs); the
                // read loop would hit EOF immediately and treat
                // file_list as the empty reference set, which is the
                // correct cleanup behaviour. Avoid turning that into a
                // mirror-cleanup failure.
                Self::Raw => Ok(()),
                // For compressed formats an empty file is malformed:
                // both gzip and xz require at least a header.
                Self::Gz | Self::Xz => {
                    warn!("Packages file `{filename}` has zero size");
                    Err(ProxyCacheError::Io(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "zero size",
                    )))
                }
            };
        };

        let decompressed_limit = decompressed_limit(compressed_size);

        let reader: &mut (dyn AsyncBufRead + Unpin + Send) = match self {
            Self::Raw => {
                let limited = LimitedReader::new(file, decompressed_limit);

                &mut tokio::io::BufReader::with_capacity(buffer_size, limited)
            }
            Self::Gz => {
                let file_reader = tokio::io::BufReader::with_capacity(buffer_size, file);
                let decoder = async_compression::tokio::bufread::GzipDecoder::new(file_reader);
                let limited = LimitedReader::new(decoder, decompressed_limit);

                &mut tokio::io::BufReader::with_capacity(buffer_size, limited)
            }
            Self::Xz => {
                let file_reader = tokio::io::BufReader::with_capacity(buffer_size, file);
                let decoder = xz_decoder(file_reader);
                let limited = LimitedReader::new(decoder, decompressed_limit);

                &mut tokio::io::BufReader::with_capacity(buffer_size, limited)
            }
        };

        let mut buffer = String::with_capacity(128);
        let mut line_buf: Vec<u8> = Vec::with_capacity(128);
        let mut stanza = Stanza::new();
        loop {
            buffer.clear();
            match read_line_capped(
                &mut *reader,
                &mut buffer,
                &mut line_buf,
                MAX_METADATA_LINE_LEN,
            )
            .await
            {
                Ok(CappedLine::Eof) => {
                    // Flush the final stanza if the Packages file doesn't end
                    // with a blank line.
                    if !stanza.is_empty() {
                        flush_stanza(&mut stanza, file_list, ctx).await;
                    }
                    return Ok(());
                }
                Err(err) => {
                    error!(
                        "Failed to read Packages file `{filename}` (may exceed size limit):  {err}"
                    );
                    return Err(err.into());
                }
                Ok(CappedLine::Skipped) => {
                    // A line longer than MAX_METADATA_LINE_LEN can't be one
                    // of the fields the stanza parser cares about (Filename,
                    // SHA256, SHA512 are all well under the cap); some
                    // packages legitimately ship multi-kilobyte `Provides:`
                    // or `Depends:` fields. Treat it as a non-blank line so
                    // the stanza isn't flushed prematurely.
                }
                Ok(CappedLine::Line { .. }) => {
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

/// The only two cache layouts that can host a `Packages` index. Replaces
/// passing the full `CacheLayout` into the fetcher, which forced three
/// unreachable match arms.
#[derive(Clone, Copy)]
pub(super) enum PackagesLayout {
    Dists,
    Flat,
}

impl PackagesLayout {
    pub(super) fn cache_layout(self) -> CacheLayout {
        match self {
            Self::Dists => CacheLayout::Dists,
            Self::Flat => CacheLayout::Flat,
        }
    }

    pub(super) fn resource_kind(self) -> ResourceKind {
        match self {
            Self::Dists => ResourceKind::Packages,
            Self::Flat => ResourceKind::FlatMetadata,
        }
    }
}

/// Typed reason a cleanup `Packages` fetch failed. Replaces the bare `StatusCode`
/// error channel so an upstream transport failure surfaces its real reason (e.g.
/// `... timed out`) in the cleanup decision log instead of a laundered
/// `502 Bad Gateway`. `status` is retained as the best-known status (a real upstream
/// code, or a `BAD_GATEWAY` sentinel); `upstream` is `Some` only when the upstream
/// fetch itself failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct FetchFailure {
    pub(super) status: StatusCode,
    pub(super) upstream: Option<UpstreamFetchError>,
}

impl std::fmt::Display for FetchFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.upstream {
            Some(upstream) => upstream.fmt(f),
            None => write!(f, "{}", self.status),
        }
    }
}

/// Try each of `.xz`, `.gz`, raw in turn — first format that returns 200 wins.
/// Each request is a self-issued `process_cache_request` against `base_uri` +
/// extension; the caller supplies the per-format `debname` and the
/// `PackagesLayout` under which to cache the result.
pub(super) async fn try_fetch_packages_file<F>(
    mirror: &Mirror,
    base_uri: &str,
    layout: PackagesLayout,
    debname_for: F,
    appstate: &AppState,
) -> Result<(Response<ProxyCacheBody>, PackageFormat), FetchFailure>
where
    F: Fn(PackageFormat) -> String,
{
    let resource_kind = layout.resource_kind();

    let mut uri_buffer = String::with_capacity(base_uri.len() + 3);
    // Remember a representative missing-ish status to surface after every
    // format fails. AWS S3 returns 403 (not 404) for a missing object when
    // the requester lacks `s3:ListBucket`, so we must not abort the
    // fallback chain on the first non-200 response — but the caller's
    // diagnostic log should still see the most informative upstream status
    // rather than a synthetic 404. Preference order: 403/410 (specific)
    // beat 404 (generic); among non-404 statuses, the first one seen wins.
    let mut last_missing: Option<StatusCode> = None;

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
            client: ClientInfo::new_cleanup(),
            request_received_at: PreciseInstant::now(),
            mirror: mirror.clone(),
            aliased_host: None,
            debname: debname_for(pkgfmt),
            cached_flavor: CachedFlavor::Volatile,
            layout: layout.cache_layout(),
            resource_kind,
        };

        let mut response = process_cache_request(conn_details, req, appstate.clone()).await;

        // An upstream-fetch failure (timeout/connect/transport) is laundered into a
        // synthetic 502 by process_cache_request but carries the real reason as a
        // response extension. Recover it so the cleanup decision log names the
        // transport error rather than a misleading "502 Bad Gateway".
        // request_with_retry already logged the transport error -- don't re-warn.
        if let Some(upstream) = response.extensions_mut().remove::<UpstreamFetchError>() {
            return Err(FetchFailure {
                status: StatusCode::BAD_GATEWAY,
                upstream: Some(upstream),
            });
        }

        let status = response.status();

        if status == StatusCode::OK {
            return Ok((response, pkgfmt));
        }

        // Treat "missing-ish" upstream statuses as "try the next format":
        // 404 Not Found, 403 Forbidden (S3 on missing object without
        // ListBucket), 410 Gone. Anything else (5xx, 401, network failure
        // mapped to 502 by process_cache_request) is fatal for this format
        // chain — surface it immediately rather than silently masking it.
        let _: Never = match status {
            StatusCode::NOT_FOUND | StatusCode::FORBIDDEN | StatusCode::GONE => {
                debug!("Cleanup request {uri} unavailable ({status})");
                // Promote 404 to a more specific status (403/410) when one
                // shows up later in the chain; otherwise stick with the
                // first non-404 we saw.
                if last_missing.is_none_or(|prev| {
                    prev == StatusCode::NOT_FOUND && status != StatusCode::NOT_FOUND
                }) {
                    last_missing = Some(status);
                }
                continue;
            }
            _ => {
                warn!("Cleanup request {uri} failed with status code {status}");
                return Err(FetchFailure {
                    status,
                    upstream: None,
                });
            }
        };
    }

    Err(FetchFailure {
        status: last_missing.unwrap_or(StatusCode::NOT_FOUND),
        upstream: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::path::PathBuf;

    use crate::cleanup::engine::SpanClass;
    use crate::{
        config::ClientHost,
        deb_mirror::MirrorKind,
        index_parser::{HashAlgo, hex_decode_exact, parse_filename_field, parse_hex_field},
        nonzero,
    };

    /// Build a `Deb`-class candidate for the reduce tests (the reduce path only
    /// reads `candidate.path`).
    fn cand(path: PathBuf) -> Candidate {
        Candidate {
            path,
            class: SpanClass::Deb,
        }
    }

    #[test]
    fn packages_layout_maps_cache_layout_and_resource_kind() {
        assert!(matches!(
            PackagesLayout::Dists.cache_layout(),
            CacheLayout::Dists
        ));
        assert!(matches!(
            PackagesLayout::Flat.cache_layout(),
            CacheLayout::Flat
        ));
        assert!(matches!(
            PackagesLayout::Dists.resource_kind(),
            ResourceKind::Packages
        ));
        assert!(matches!(
            PackagesLayout::Flat.resource_kind(),
            ResourceKind::FlatMetadata
        ));
    }

    #[test]
    fn key_mapper_maps_each_layout() {
        use std::borrow::Cow;
        // Structured: basename of the relpath.
        assert_eq!(
            KeyMapper::Basename.map("pool/main/a/abc/abc_1.0_amd64.deb"),
            Some(Cow::Borrowed("abc_1.0_amd64.deb")),
        );
        // Flat co-located: relpath verbatim.
        assert_eq!(
            KeyMapper::Relpath.map("amd64/twilio-cli_5.0.0_amd64.deb"),
            Some(Cow::Borrowed("amd64/twilio-cli_5.0.0_amd64.deb")),
        );
        // Flat walk-up: strip the prefix, drop siblings outside it.
        let km = KeyMapper::RelpathUnderPrefix { prefix: "amd64/" };
        assert_eq!(km.map("amd64/pkg.deb"), Some(Cow::Borrowed("pkg.deb")));
        assert_eq!(km.map("arm64/sibling.deb"), None);
    }

    #[test]
    fn body_is_incomplete_only_flags_short_announced_bodies() {
        // No announced length (chunked / volatile-unknown / legit empty): the
        // byte count can't prove truncation, so never "incomplete".
        assert!(!body_is_incomplete(None, 0));
        assert!(!body_is_incomplete(None, 1234));
        // Announced an exact length but buffered fewer bytes -> truncated.
        assert!(body_is_incomplete(Some(100), 0)); // the reported zero-byte abort
        assert!(body_is_incomplete(Some(100), 40)); // raw over-eviction guard
        // Exact length fully buffered.
        assert!(!body_is_incomplete(Some(100), 100));
        // Defensive: a zero announced length is never short (the proxy never
        // actually emits Content-Length: 0, but the predicate must not flag it).
        assert!(!body_is_incomplete(Some(0), 0));
    }

    #[tokio::test]
    async fn packages_body_to_memfd_counts_bytes_and_rewinds() {
        use tokio::io::AsyncReadExt as _;

        let config: crate::config::Config = toml::from_str("").expect("default config");
        let payload = b"Package: hello\nFilename: pool/main/h/hello/hello_1_amd64.deb\n\n";
        let mut body = crate::full_body(bytes::Bytes::from_static(payload));

        let (mut file, written) =
            packages_body_to_memfd("apt_cacher_rs_test_count", &mut body, &config)
                .await
                .expect("buffer body");

        assert_eq!(
            written,
            payload.len() as u64,
            "byte count must match payload"
        );

        let mut roundtrip = Vec::new();
        file.read_to_end(&mut roundtrip)
            .await
            .expect("read memfd back");
        assert_eq!(roundtrip, payload, "file must be rewound to offset 0");
    }

    #[tokio::test]
    async fn body_to_file_rejects_body_over_cap() {
        let config: crate::config::Config = toml::from_str("").expect("default config");
        // A single 4 KiB data frame against a 1 KiB cap: the first chunk already
        // overshoots, so buffering must bail with an error (not truncate, which
        // would silently shrink the reference set and over-evict).
        let mut body = crate::full_body(bytes::Bytes::from(vec![b'x'; 4096]));
        let memfd = MemfdOptions::new()
            .create("apt_cacher_rs_test_over_cap")
            .expect("memfd");
        let file = tokio::fs::File::from_std(memfd.into_file());

        let res = body_to_file(&mut body, file, nonzero!(1024), &config).await;
        assert!(
            res.is_err(),
            "a body exceeding the cap must error rather than buffer unbounded"
        );
    }

    #[tokio::test]
    async fn body_to_file_accepts_body_at_cap() {
        let config: crate::config::Config = toml::from_str("").expect("default config");
        // Exactly at the cap: `written > max_bytes` is strict, so this is kept.
        let mut body = crate::full_body(bytes::Bytes::from(vec![b'y'; 1024]));
        let memfd = MemfdOptions::new()
            .create("apt_cacher_rs_test_at_cap")
            .expect("memfd");
        let file = tokio::fs::File::from_std(memfd.into_file());

        let (_file, written) = body_to_file(&mut body, file, nonzero!(1024), &config)
            .await
            .expect("a body exactly at the cap must buffer successfully");
        assert_eq!(written, 1024);
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

    #[tokio::test]
    async fn process_stanza_flat_prefix_strips_in_subtree_and_drops_siblings() {
        // Regression guard for the walk-up flat-cleanup case: when a flat
        // mirror at `apt/amd64` reuses a Packages index fetched at the
        // ancestor `apt/`, `Filename:` values are relative to `apt/`. The
        // process_stanza prefix logic must (a) ignore sibling-subtree
        // entries (`arm64/*`), and (b) strip the `amd64/` prefix to find
        // the basename-keyed entry inside our subtree.
        use std::num::NonZero;

        let mut file_list: HashMap<String, Candidate> = HashMap::new();
        file_list.insert(
            "pkg.deb".to_owned(),
            cand(PathBuf::from("/tmp/cache/pkg.deb")),
        );
        file_list.insert(
            "other.deb".to_owned(),
            cand(PathBuf::from("/tmp/cache/other.deb")),
        );

        let mirror = Mirror::new(
            ClientHost::new("example.com".to_owned()).expect("valid host"),
            None::<NonZero<u16>>,
            "apt/amd64".to_owned(),
            MirrorKind::Flat,
        );
        let mut mismatch_files = 0u64;
        let mut mismatch_bytes = 0u64;

        // Sibling subtree: `arm64/sibling.deb` does not start with the
        // `amd64/` prefix — must be a no-op on file_list.
        {
            let km = KeyMapper::RelpathUnderPrefix { prefix: "amd64/" };
            let mut ctx = ReduceContext {
                mirror: &mirror,
                layout: CacheLayout::Flat,
                mismatch_files: &mut mismatch_files,
                mismatch_bytes: &mut mismatch_bytes,
                keymap: &km,
            };
            let mut stanza = Stanza::new();
            stanza.ingest("Filename: arm64/sibling.deb\n");
            process_stanza(&stanza, &mut file_list, &mut ctx).await;
        }
        assert_eq!(file_list.len(), 2);
        assert!(file_list.contains_key("pkg.deb"));
        assert!(file_list.contains_key("other.deb"));

        // In-subtree: `amd64/pkg.deb` strips to `pkg.deb`; with no SHA
        // advertised, the stanza warn-retains and removes the lookup key.
        {
            let km = KeyMapper::RelpathUnderPrefix { prefix: "amd64/" };
            let mut ctx = ReduceContext {
                mirror: &mirror,
                layout: CacheLayout::Flat,
                mismatch_files: &mut mismatch_files,
                mismatch_bytes: &mut mismatch_bytes,
                keymap: &km,
            };
            let mut stanza = Stanza::new();
            stanza.ingest("Filename: amd64/pkg.deb\n");
            process_stanza(&stanza, &mut file_list, &mut ctx).await;
        }
        assert!(!file_list.contains_key("pkg.deb"));
        assert!(file_list.contains_key("other.deb"));
    }

    #[test]
    fn decompressed_limit_ratio_caps_small_input() {
        // A tiny compressed file: the ratio cap (size * MAX_DECOMPRESSION_RATIO) dominates.
        assert_eq!(
            decompressed_limit(nonzero!(1000)),
            MAX_DECOMPRESSION_RATIO.checked_mul(nonzero!(1000)).unwrap()
        );
    }

    #[test]
    fn decompressed_limit_absolute_caps_large_input() {
        // A huge compressed file: the absolute cap dominates.
        assert_eq!(
            decompressed_limit(nonzero!(u64::MAX)),
            MAX_DECOMPRESSED_PACKAGES_SIZE
        );
    }

    #[tokio::test]
    async fn reduce_file_list_rejects_decompression_bomb() {
        use std::num::NonZero;

        use async_compression::tokio::write::GzipEncoder;
        use tokio::io::AsyncWriteExt as _;

        // 4 MiB of newlines compresses to a few KiB -- a ratio far above the cap.
        let raw = vec![b'\n'; 4 * 1024 * 1024];
        let mut encoder = GzipEncoder::new(Vec::new());
        encoder.write_all(&raw).await.expect("gzip write");
        encoder.shutdown().await.expect("gzip finish");
        let compressed = encoder.into_inner();

        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("Packages.gz");
        tokio::fs::write(&path, &compressed)
            .await
            .expect("write fixture");
        let file = tokio::fs::File::open(&path).await.expect("open fixture");

        let config: crate::config::Config = toml::from_str("").expect("default config");
        // Mirror the EXACT Mirror / ReduceContext construction used by the
        // existing process_stanza_flat_prefix_strips_in_subtree_and_drops_siblings
        // test in this module.
        let mirror = Mirror::new(
            ClientHost::new("example.com".to_owned()).expect("valid host"),
            None::<NonZero<u16>>,
            "apt/amd64".to_owned(),
            MirrorKind::Flat,
        );
        // A non-matching entry keeps `file_list` non-empty so the reducer
        // streams the whole (bomb) input instead of early-returning.
        let mut file_list: HashMap<String, Candidate> = HashMap::new();
        file_list.insert(
            "never-matched.deb".to_owned(),
            cand(PathBuf::from("/tmp/x.deb")),
        );
        let mut mismatch_files = 0u64;
        let mut mismatch_bytes = 0u64;
        let km = KeyMapper::RelpathUnderPrefix { prefix: "amd64/" };
        let mut ctx = ReduceContext {
            mirror: &mirror,
            layout: CacheLayout::Flat,
            mismatch_files: &mut mismatch_files,
            mismatch_bytes: &mut mismatch_bytes,
            keymap: &km,
        };

        let result = PackageFormat::Gz
            .reduce_file_list(file, "Packages.gz", &mut file_list, &mut ctx, &config)
            .await;
        assert!(
            result.is_err(),
            "a decompression bomb must abort reduce_file_list"
        );
    }

    #[tokio::test]
    async fn reduce_file_list_skips_overlong_line_and_keeps_parsing() {
        use std::num::NonZero;

        use sha2::{Digest as _, Sha256};

        use crate::index_parser::hex_encode;

        // Pre-compute SHA256(b"payload") so the stanza yields a `Match`
        // verdict — the `Mismatch` path would call into the cache_metadata
        // singleton which isn't initialized under `cargo test`.
        let deb_body: &[u8] = b"payload";
        let deb_hash: [u8; 32] = Sha256::digest(deb_body).into();

        // Build a stanza whose `Provides:` field is far longer than the
        // per-line cap (mirroring the real `experimental_main` layout where
        // packages like `librust-ruma` carry ~19 KiB Provides lists) — the
        // parser must skip the line and still extract Filename+SHA256.
        let mut raw = Vec::new();
        raw.extend_from_slice(b"Package: dummy\n");
        raw.extend_from_slice(b"Filename: pool/d/dummy/dummy_1.0_amd64.deb\n");
        raw.extend_from_slice(b"Provides: ");
        raw.resize(raw.len() + MAX_METADATA_LINE_LEN + 1024, b'a');
        raw.push(b'\n');
        let sha_line = format!("SHA256: {}\n", hex_encode(&deb_hash));
        raw.extend_from_slice(sha_line.as_bytes());
        raw.extend_from_slice(b"\n");

        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("Packages");
        tokio::fs::write(&path, &raw).await.expect("write fixture");
        let file = tokio::fs::File::open(&path).await.expect("open fixture");

        let config: crate::config::Config = toml::from_str("").expect("default config");
        let mirror = Mirror::new(
            ClientHost::new("example.com".to_owned()).expect("valid host"),
            None::<NonZero<u16>>,
            "debian".to_owned(),
            MirrorKind::Structured,
        );
        // `dummy_1.0_amd64.deb` is the structured-lookup-key (basename) of
        // the Filename: above; reaching `flush_stanza` with the stanza
        // intact removes the entry from the candidate list, proving the
        // parser kept its place through the oversize line.
        let mut file_list: HashMap<String, Candidate> = HashMap::new();
        let deb_path = dir.path().join("dummy_1.0_amd64.deb");
        tokio::fs::write(&deb_path, deb_body)
            .await
            .expect("write deb");
        file_list.insert("dummy_1.0_amd64.deb".to_owned(), cand(deb_path));
        file_list.insert(
            "keep-me.deb".to_owned(),
            cand(PathBuf::from("/tmp/keep.deb")),
        );
        let mut mismatch_files = 0u64;
        let mut mismatch_bytes = 0u64;
        let km = KeyMapper::Basename;
        let mut ctx = ReduceContext {
            mirror: &mirror,
            layout: CacheLayout::StructuredPool,
            mismatch_files: &mut mismatch_files,
            mismatch_bytes: &mut mismatch_bytes,
            keymap: &km,
        };

        PackageFormat::Raw
            .reduce_file_list(file, "Packages", &mut file_list, &mut ctx, &config)
            .await
            .expect("oversize lines must be skipped, not aborted");

        assert!(
            !file_list.contains_key("dummy_1.0_amd64.deb"),
            "matching stanza after a skipped line must still remove the file"
        );
        assert!(
            file_list.contains_key("keep-me.deb"),
            "unrelated entries must be left in place"
        );
    }

    /// A zero-length raw `Packages` file is a valid empty stanza set
    /// (e.g. a freshly-created component with no published debs) and
    /// must not abort the per-mirror cleanup.
    #[tokio::test]
    async fn reduce_file_list_accepts_empty_raw_packages() {
        use std::num::NonZero;

        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("Packages");
        tokio::fs::write(&path, b"").await.expect("write empty");
        let file = tokio::fs::File::open(&path).await.expect("open empty");

        let config: crate::config::Config = toml::from_str("").expect("default config");
        let mirror = Mirror::new(
            ClientHost::new("example.com".to_owned()).expect("valid host"),
            None::<NonZero<u16>>,
            "debian".to_owned(),
            MirrorKind::Structured,
        );
        let mut file_list: HashMap<String, Candidate> = HashMap::new();
        file_list.insert(
            "keep-me.deb".to_owned(),
            cand(PathBuf::from("/tmp/keep.deb")),
        );
        let mut mismatch_files = 0u64;
        let mut mismatch_bytes = 0u64;
        let km = KeyMapper::Basename;
        let mut ctx = ReduceContext {
            mirror: &mirror,
            layout: CacheLayout::StructuredPool,
            mismatch_files: &mut mismatch_files,
            mismatch_bytes: &mut mismatch_bytes,
            keymap: &km,
        };

        PackageFormat::Raw
            .reduce_file_list(file, "Packages", &mut file_list, &mut ctx, &config)
            .await
            .expect("an empty raw Packages file must be treated as zero stanzas");

        assert!(
            file_list.contains_key("keep-me.deb"),
            "empty Packages must leave the candidate list untouched"
        );
    }

    #[test]
    fn fetch_failure_display_prefers_upstream_reason() {
        let with_upstream = FetchFailure {
            status: StatusCode::BAD_GATEWAY,
            upstream: Some(UpstreamFetchError {
                reason: "connection error:  timed out".to_owned(),
            }),
        };
        // The laundered 502 must NOT show; the real transport reason does.
        assert_eq!(with_upstream.to_string(), "connection error:  timed out");

        let status_only = FetchFailure {
            status: StatusCode::NOT_FOUND,
            upstream: None,
        };
        assert_eq!(status_only.to_string(), "404 Not Found");
    }

    #[test]
    fn fetch_failure_equality_spans_the_whole_struct() {
        let a = FetchFailure {
            status: StatusCode::BAD_GATEWAY,
            upstream: Some(UpstreamFetchError {
                reason: "timed out".to_owned(),
            }),
        };
        let b = FetchFailure {
            status: StatusCode::BAD_GATEWAY,
            upstream: Some(UpstreamFetchError {
                reason: "connection refused".to_owned(),
            }),
        };
        // Two upstream failures with different reasons are NOT equal (drives the
        // flat-root suffix-suppression in engine.rs).
        assert_ne!(a, b);
        assert_eq!(a, a);
    }
}
