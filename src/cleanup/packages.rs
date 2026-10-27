use std::ffi::{OsStr, OsString};
use std::io;
use std::num::NonZero;
use std::path::Path;

use hashbrown::HashMap;
use tracing::{debug, error, warn};

use crate::{
    cache_layout::CacheLayout,
    deb_mirror::Mirror,
    error::ErrorReport,
    index_parser::{Stanza, StanzaStream, hex_encode, structured_lookup_key},
    limits::{PackagesCompression, check_packages_file_size, decompressed_limit, packages_reader},
    metrics,
    mirror_health::{self, MirrorFault},
};

use super::engine::{SpanClass, UnitStats};
use super::fetch::FetchedPackages;
use super::sweep::invalidate_metadata_for;
use super::verify::{Verdict, verify_cache_file};

/// How a `Filename:` value from a Packages stanza maps to a key in the
/// scanned candidate map.
#[derive(Clone, Copy)]
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
    pub(super) fn map<'a>(&self, filename: &'a str) -> Option<&'a str> {
        match self {
            Self::Basename => Some(structured_lookup_key(filename)),
            Self::Relpath => Some(filename),
            Self::RelpathUnderPrefix { prefix } => filename.strip_prefix(prefix),
        }
    }
}

/// Per-call context for [`reduce_file_list`]: needed to invalidate
/// per-file `cache_metadata` entries and to attribute checksum-mismatch
/// removals back to the per-mirror `CleanupDone` totals.
pub(super) struct ReduceContext<'a> {
    /// Tree root the candidate keys are relative to; a matched key is rejoined
    /// onto it to reach the cached file.
    pub(super) root: &'a Path,
    pub(super) mirror: &'a Mirror,
    pub(super) layout: CacheLayout,
    /// The unit's running tally; checksum-mismatch evictions are accounted
    /// straight into it, so deletions performed before a mid-cascade group
    /// failure are never lost.
    pub(super) tally: &'a mut UnitStats,
    /// Derives the lookup key from a `Filename:` relpath.
    pub(super) keymap: KeyMapper<'a>,
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
async fn process_stanza(
    stanza: &Stanza,
    file_list: &mut HashMap<OsString, SpanClass>,
    ctx: &mut ReduceContext<'_>,
) {
    let Some(filename) = stanza.filename() else {
        return;
    };

    let Some(lookup_key) = ctx.keymap.map(filename) else {
        return;
    };

    // Every path below drops the entry from the reference set, so take it out
    // once rather than looking it up again per exit.
    if file_list.remove(OsStr::new(lookup_key)).is_none() {
        return;
    }
    let Some((algo, expected)) = stanza.chosen() else {
        // Retained without verification; `StanzaStream` already warned about
        // the digest-less stanza.
        return;
    };
    let path = ctx.root.join(lookup_key);

    // No pre-verify stat: `verify_file_sync` opens the file `O_NOFOLLOW |
    // O_NONBLOCK` and `fstat`s the descriptor it actually hashed, so it detects
    // a concurrent type swap without a second syscall (and without the
    // lstat-then-open race an extra stat would only narrow).
    match verify_cache_file(path.clone(), algo, expected.to_vec()).await {
        Verdict::Match => {}
        Verdict::NonRegular => {
            warn!(
                "Cache file `{}` changed to non-regular between cleanup-collect and verify (concurrent swap); retaining without verification",
                path.display(),
            );
        }
        Verdict::Mismatch {
            computed,
            size: pre_size,
        } => {
            warn!(
                "Cache file `{}` failed {} verification (expected {}, computed {}); removing it",
                path.display(),
                algo.as_str(),
                hex_encode(expected),
                hex_encode(&computed),
            );
            if let Err(err) = tokio::fs::remove_file(&path).await {
                ctx.tally.io_failures += 1;
                metrics::CACHE_IO_FAILURE.increment();
                error!(
                    "Failed to remove checksum-mismatched cache file `{}`; retaining it:  {}",
                    path.display(),
                    ErrorReport(&err)
                );
            } else {
                invalidate_metadata_for(&path, ctx.mirror, ctx.layout);
                metrics::CLEANUP_CHECKSUM_MISMATCHES.increment();
                mirror_health::record(ctx.mirror, MirrorFault::Checksum);
                ctx.tally.record_mismatch(pre_size);
            }
        }
        Verdict::Vanished => {
            debug!(
                "Cache entry `{}` vanished before it could be verified; skipping it",
                path.display(),
            );
        }
        Verdict::Raced => {
            warn!(
                "Cache file `{}` changed during {} verification; retaining (concurrent re-cache)",
                path.display(),
                algo.as_str(),
            );
        }
        Verdict::IoError(err) => {
            ctx.tally.io_failures += 1;
            error!(
                "Failed to verify cache file `{}` against its {} digest; retaining it:  {}",
                path.display(),
                algo.as_str(),
                ErrorReport(&err),
            );
        }
    }
}

/// Why a fetched `Packages` index could not be reduced against the candidate
/// set.  Carries the cause only: the resolver receiving it decides the
/// consequence (bail the mirror, continue with the next index source, fall
/// back to age-based retention) and logs the one line, with this rendered
/// through `ErrorReport` after it.  `filename` is the fetched index's
/// [`FetchedPackages::name`], which identifies the origin's index.
#[derive(Debug, thiserror::Error)]
pub(super) enum ReduceError {
    /// A gzip/xz index of zero bytes is malformed (both formats need at least
    /// a header), never "no stanzas" - only a raw index may be empty.
    #[error("compressed Packages index `{filename}` is zero bytes")]
    ZeroSizeCompressed { filename: String },
    /// Larger than `limits::packages_file_cap` allows; refused undecoded.
    #[error("Packages index `{filename}` is too large to decode")]
    TooLarge {
        filename: String,
        #[source]
        source: io::Error,
    },
    /// Decode/read failure, including the decompressed-size and line caps
    /// and a decompression bomb.
    #[error("failed to read Packages index `{filename}` (may exceed the size or line limit)")]
    Read {
        filename: String,
        #[source]
        source: io::Error,
    },
}

/// Stream a (possibly compressed) Debian `Packages` file stanza by stanza,
/// reducing the candidate `file_list` by basename and verifying matched
/// cache files against the stanza's `SHA256:`/`SHA512:` digest.
///
/// Cleanup is conservative about an index it cannot read in full: an unreadable
/// or malformed file bails the mirror this cycle rather than reconciling against
/// a partial reference set (which would grace-sweep still-referenced debs). That
/// is the deliberate difference from `integrity::ingest_packages_file`, which
/// shares the decode ladder via [`packages_reader`] and the stanza loop via
/// [`StanzaStream`] but degrades to a less-populated registry instead.  The
/// `Err` is the cause alone; the resolver logs it with its consequence.
pub(super) async fn reduce_file_list(
    index: FetchedPackages,
    file_list: &mut HashMap<OsString, SpanClass>,
    ctx: &mut ReduceContext<'_>,
    buffer_size: usize,
) -> Result<(), ReduceError> {
    debug_assert!(!file_list.is_empty(), "avoid unnecessary work");

    let FetchedPackages {
        compression,
        name: filename,
        input,
        len,
    } = index;

    check_packages_file_size(compression, len).map_err(|source| ReduceError::TooLarge {
        filename: filename.clone(),
        source,
    })?;

    let Some(compressed_size) = NonZero::new(len) else {
        return match compression {
            // A raw Packages file with zero stanzas is legal (e.g.
            // a freshly-created component with no published debs); the
            // read loop would hit EOF immediately and treat
            // file_list as the empty reference set, which is the
            // correct cleanup behaviour. Avoid turning that into a
            // mirror-cleanup failure.
            PackagesCompression::Raw => Ok(()),
            // For compressed formats an empty file is malformed:
            // both gzip and xz require at least a header.
            PackagesCompression::Gz | PackagesCompression::Xz => {
                Err(ReduceError::ZeroSizeCompressed { filename })
            }
        };
    };

    let reader = packages_reader(
        input,
        compression,
        decompressed_limit(Some(compressed_size)),
        buffer_size,
    )
    .await;

    // `filename` is the synthetic index name, so name the mirror as well.
    let mut stanzas = StanzaStream::new(
        reader,
        Stanza::new().with_source(format!("mirror {} index `{filename}`", ctx.mirror)),
    );
    loop {
        match stanzas.next().await {
            Ok(Some(stanza)) => {
                process_stanza(stanza, file_list, ctx).await;
                // Every candidate is referenced: nothing left to reduce.
                if file_list.is_empty() {
                    return Ok(());
                }
            }
            Ok(None) => return Ok(()),
            Err(source) => {
                return Err(ReduceError::Read { filename, source });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    const BUFFER_SIZE: usize = 32 * 1024;

    use super::*;

    use crate::{
        config::ClientHost,
        deb_mirror::MirrorKind,
        index_parser::{HashAlgo, hex_decode_exact, parse_filename_field},
        limits::{MAX_COMPRESSED_PACKAGES_SIZE, MAX_METADATA_LINE_LEN, PackagesInput},
        test_support::structured_mirror,
    };

    /// A test fixture as the fetch would hand it over: the whole file,
    /// sized by a stat.
    async fn fetched(
        compression: PackagesCompression,
        file: tokio::fs::File,
        name: &str,
    ) -> FetchedPackages {
        let len = file.metadata().await.expect("stat fixture").len();
        FetchedPackages {
            compression,
            name: name.to_owned(),
            input: PackagesInput::File(file),
            len,
        }
    }

    /// A candidate map for the reduce tests: every entry is `Deb`-class and
    /// keyed by its path relative to the `ReduceContext` root.
    fn cands(keys: &[&str]) -> HashMap<OsString, SpanClass> {
        keys.iter()
            .map(|k| (OsString::from(*k), SpanClass::Deb))
            .collect()
    }

    #[test]
    fn key_mapper_maps_each_layout() {
        // Structured: basename of the relpath.
        assert_eq!(
            KeyMapper::Basename.map("pool/main/a/abc/abc_1.0_amd64.deb"),
            Some("abc_1.0_amd64.deb"),
        );
        // Flat co-located: relpath verbatim.
        assert_eq!(
            KeyMapper::Relpath.map("amd64/twilio-cli_5.0.0_amd64.deb"),
            Some("amd64/twilio-cli_5.0.0_amd64.deb"),
        );
        // Flat walk-up: strip the prefix, drop siblings outside it.
        let km = KeyMapper::RelpathUnderPrefix { prefix: "amd64/" };
        assert_eq!(km.map("amd64/pkg.deb"), Some("pkg.deb"));
        assert_eq!(km.map("arm64/sibling.deb"), None);
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
        assert_eq!(parse_filename_field("Filename: a//b.deb\n"), None);
        // A leading `./` is NOT traversal and is normalised away rather than
        // rejected (flat archives publish every stanza that way); a `..`
        // behind it still is.
        assert_eq!(
            parse_filename_field("Filename: ./foo.deb\n"),
            Some("foo.deb"),
        );
        assert_eq!(parse_filename_field("Filename: ./../escape.deb\n"), None);
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
            "abc_1.0_amd64.deb",
        );
        assert_eq!(
            structured_lookup_key("abc_1.0_amd64.deb"),
            "abc_1.0_amd64.deb",
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
        assert_eq!(s.filename(), None);
        assert_eq!(s.chosen(), None);
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

        let mut file_list = cands(&["pkg.deb", "other.deb"]);

        let mirror = Mirror::new(
            ClientHost::new("example.com").expect("valid host"),
            None::<NonZero<u16>>,
            "apt/amd64".to_owned(),
            MirrorKind::Flat,
        );
        let mut tally = UnitStats::default();

        // Sibling subtree: `arm64/sibling.deb` does not start with the
        // `amd64/` prefix — must be a no-op on file_list.
        {
            let mut ctx = ReduceContext {
                root: Path::new("/tmp/cache"),
                mirror: &mirror,
                layout: CacheLayout::Flat,
                tally: &mut tally,
                keymap: KeyMapper::RelpathUnderPrefix { prefix: "amd64/" },
            };
            let mut stanza = Stanza::new();
            stanza.ingest("Filename: arm64/sibling.deb\n");
            process_stanza(&stanza, &mut file_list, &mut ctx).await;
        }
        assert_eq!(file_list.len(), 2);
        assert!(file_list.contains_key(OsStr::new("pkg.deb")));
        assert!(file_list.contains_key(OsStr::new("other.deb")));

        // In-subtree: `amd64/pkg.deb` strips to `pkg.deb`; with no SHA
        // advertised, the stanza warn-retains and removes the lookup key.
        {
            let mut ctx = ReduceContext {
                root: Path::new("/tmp/cache"),
                mirror: &mirror,
                layout: CacheLayout::Flat,
                tally: &mut tally,
                keymap: KeyMapper::RelpathUnderPrefix { prefix: "amd64/" },
            };
            let mut stanza = Stanza::new();
            stanza.ingest("Filename: amd64/pkg.deb\n");
            process_stanza(&stanza, &mut file_list, &mut ctx).await;
        }
        assert!(!file_list.contains_key(OsStr::new("pkg.deb")));
        assert!(file_list.contains_key(OsStr::new("other.deb")));
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

        // Mirror the EXACT Mirror / ReduceContext construction used by the
        // existing process_stanza_flat_prefix_strips_in_subtree_and_drops_siblings
        // test in this module.
        let mirror = Mirror::new(
            ClientHost::new("example.com").expect("valid host"),
            None::<NonZero<u16>>,
            "apt/amd64".to_owned(),
            MirrorKind::Flat,
        );
        // A non-matching entry keeps `file_list` non-empty so the reducer
        // streams the whole (bomb) input instead of early-returning.
        let mut file_list = cands(&["never-matched.deb"]);
        let mut tally = UnitStats::default();
        let mut ctx = ReduceContext {
            root: Path::new("/tmp"),
            mirror: &mirror,
            layout: CacheLayout::Flat,
            tally: &mut tally,
            keymap: KeyMapper::RelpathUnderPrefix { prefix: "amd64/" },
        };

        let result = reduce_file_list(
            fetched(PackagesCompression::Gz, file, "Packages.gz").await,
            &mut file_list,
            &mut ctx,
            BUFFER_SIZE,
        )
        .await;
        let err = result.expect_err("a decompression bomb must abort reduce_file_list");
        assert!(
            matches!(err, ReduceError::Read { ref filename, .. } if filename == "Packages.gz"),
            "a decompression bomb is a read failure of the named index, got {err:?}"
        );
    }

    /// A compressed index past `MAX_COMPRESSED_PACKAGES_SIZE` is refused on
    /// its size, before the decoder sees a byte (the sparse fixture holds no
    /// valid xz header, so a decode attempt would fail differently).
    #[tokio::test]
    async fn reduce_file_list_refuses_an_oversized_compressed_index_unread() {
        use std::num::NonZero;

        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("Packages.xz");
        let std_file = std::fs::File::create(&path).expect("create fixture");
        std_file
            .set_len(MAX_COMPRESSED_PACKAGES_SIZE.get() + 1)
            .expect("extend sparse");
        drop(std_file);
        let file = tokio::fs::File::open(&path).await.expect("open fixture");

        let mirror = Mirror::new(
            ClientHost::new("example.com").expect("valid host"),
            None::<NonZero<u16>>,
            "apt/amd64".to_owned(),
            MirrorKind::Flat,
        );
        let mut file_list = cands(&["never-matched.deb"]);
        let mut tally = UnitStats::default();
        let mut ctx = ReduceContext {
            root: Path::new("/tmp"),
            mirror: &mirror,
            layout: CacheLayout::Flat,
            tally: &mut tally,
            keymap: KeyMapper::RelpathUnderPrefix { prefix: "amd64/" },
        };

        let err = reduce_file_list(
            fetched(PackagesCompression::Xz, file, "Packages.xz").await,
            &mut file_list,
            &mut ctx,
            BUFFER_SIZE,
        )
        .await
        .expect_err("an oversized compressed index must bail the mirror");
        assert!(
            matches!(err, ReduceError::TooLarge { ref filename, .. } if filename == "Packages.xz"),
            "got {err:?}"
        );
        assert_eq!(file_list.len(), 1, "the candidates must be left untouched");
    }

    /// A zero-byte compressed index is malformed (gzip needs at least a
    /// header): the mirror bails with `ZeroSizeCompressed` and the candidate
    /// list is left untouched rather than reconciled against nothing.
    #[tokio::test]
    async fn reduce_file_list_rejects_empty_compressed_index() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("Packages.gz");
        tokio::fs::write(&path, b"").await.expect("write empty");
        let file = tokio::fs::File::open(&path).await.expect("open empty");

        let mirror = structured_mirror("example.com", "debian");
        let mut file_list = cands(&["keep-me.deb"]);
        let mut tally = UnitStats::default();
        let mut ctx = ReduceContext {
            root: Path::new("/tmp"),
            mirror: &mirror,
            layout: CacheLayout::StructuredPool,
            tally: &mut tally,
            keymap: KeyMapper::Basename,
        };

        let err = reduce_file_list(
            fetched(PackagesCompression::Gz, file, "Packages.gz").await,
            &mut file_list,
            &mut ctx,
            BUFFER_SIZE,
        )
        .await
        .expect_err("an empty compressed index must bail the mirror");
        assert!(
            matches!(err, ReduceError::ZeroSizeCompressed { ref filename } if filename == "Packages.gz"),
            "got {err:?}"
        );
        assert_eq!(file_list.len(), 1);
        assert!(
            file_list.contains_key(OsStr::new("keep-me.deb")),
            "a rejected index must leave the candidate list untouched"
        );
    }

    #[tokio::test]
    async fn reduce_file_list_skips_overlong_line_and_keeps_parsing() {
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

        let mirror = structured_mirror("example.com", "debian");
        // `dummy_1.0_amd64.deb` is the structured-lookup-key (basename) of
        // the Filename: above; reaching `StanzaStream::complete` with the stanza
        // intact removes the entry from the candidate list, proving the
        // parser kept its place through the oversize line.
        tokio::fs::write(dir.path().join("dummy_1.0_amd64.deb"), deb_body)
            .await
            .expect("write deb");
        let mut file_list = cands(&["dummy_1.0_amd64.deb", "keep-me.deb"]);
        let mut tally = UnitStats::default();
        let mut ctx = ReduceContext {
            root: dir.path(),
            mirror: &mirror,
            layout: CacheLayout::StructuredPool,
            tally: &mut tally,
            keymap: KeyMapper::Basename,
        };

        reduce_file_list(
            fetched(PackagesCompression::Raw, file, "Packages").await,
            &mut file_list,
            &mut ctx,
            BUFFER_SIZE,
        )
        .await
        .expect("oversize lines must be skipped, not aborted");

        assert!(
            !file_list.contains_key(OsStr::new("dummy_1.0_amd64.deb")),
            "matching stanza after a skipped line must still remove the file"
        );
        assert!(
            file_list.contains_key(OsStr::new("keep-me.deb")),
            "unrelated entries must be left in place"
        );
    }

    /// A zero-length raw `Packages` file is a valid empty stanza set
    /// (e.g. a freshly-created component with no published debs) and
    /// must not abort the per-mirror cleanup.
    #[tokio::test]
    async fn reduce_file_list_accepts_empty_raw_packages() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("Packages");
        tokio::fs::write(&path, b"").await.expect("write empty");
        let file = tokio::fs::File::open(&path).await.expect("open empty");

        let mirror = structured_mirror("example.com", "debian");
        let mut file_list = cands(&["keep-me.deb"]);
        let mut tally = UnitStats::default();
        let mut ctx = ReduceContext {
            root: Path::new("/tmp"),
            mirror: &mirror,
            layout: CacheLayout::StructuredPool,
            tally: &mut tally,
            keymap: KeyMapper::Basename,
        };

        reduce_file_list(
            fetched(PackagesCompression::Raw, file, "Packages").await,
            &mut file_list,
            &mut ctx,
            BUFFER_SIZE,
        )
        .await
        .expect("an empty raw Packages file must be treated as zero stanzas");

        assert!(
            file_list.contains_key(OsStr::new("keep-me.deb")),
            "empty Packages must leave the candidate list untouched"
        );
    }

    /// Contents of the one cached deb [`INDEX_RAW`] vouches for.
    const KEPT_DEB: &[u8] = b"deb";

    /// A small index: `kept` with the SHA256 of [`KEPT_DEB`], and a
    /// digest-less `nodigest` (retained without verification).
    const INDEX_RAW: &[u8] = b"Package: kept\n\
        Filename: pool/main/k/kept/kept_1_amd64.deb\n\
        SHA256: 9cfa1468c93fc18652e34a000f0c6614b0fa18f6f4887477ad9b0d36ca6a7eaa\n\
        \n\
        Package: nodigest\n\
        Filename: pool/main/n/nodigest/nodigest_1_amd64.deb\n\
        \n";

    /// [`INDEX_RAW`] through `xz -c --check=crc32` (the crate depends on no
    /// xz encoder).
    const INDEX_XZ: &[u8] = &[
        0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00, 0x00, 0x01, 0x69, 0x22, 0xde, 0x36, 0x04, 0xc0, 0x96,
        0x01, 0xcb, 0x01, 0x21, 0x01, 0x16, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x76, 0x2a,
        0xeb, 0x91, 0xe0, 0x00, 0xca, 0x00, 0x8e, 0x5d, 0x00, 0x28, 0x18, 0x48, 0x66, 0xdb, 0xda,
        0x30, 0x85, 0xfe, 0x16, 0xe8, 0x23, 0xf8, 0x32, 0xd4, 0x22, 0xe4, 0x41, 0x49, 0xd9, 0x0e,
        0xff, 0x19, 0xb9, 0xa6, 0x03, 0xb2, 0x04, 0x9c, 0x35, 0x24, 0x78, 0x7e, 0x4b, 0xc5, 0x8e,
        0xb3, 0x46, 0x54, 0x3a, 0xc7, 0x6b, 0x82, 0xd8, 0xda, 0x1e, 0xe9, 0xf6, 0x75, 0x0a, 0x6e,
        0x94, 0x89, 0xeb, 0xa4, 0x28, 0xbf, 0x63, 0xd3, 0x08, 0x7e, 0x93, 0x47, 0x0f, 0xc9, 0xc0,
        0x3c, 0x04, 0xf3, 0xbf, 0x97, 0x2a, 0x3d, 0x77, 0x9c, 0xdf, 0x51, 0x6c, 0x4d, 0xee, 0x1b,
        0xc3, 0x39, 0xca, 0x12, 0x20, 0x11, 0x55, 0x97, 0x1b, 0x1e, 0xff, 0x38, 0x25, 0xc7, 0x57,
        0xd9, 0xbb, 0x64, 0x5d, 0x50, 0x6c, 0xba, 0x3a, 0xc7, 0x64, 0xae, 0x83, 0xa3, 0x91, 0x6d,
        0xc2, 0x2d, 0x48, 0xfe, 0xc2, 0xb9, 0x03, 0xc7, 0x8e, 0x87, 0x79, 0x4f, 0x02, 0x7c, 0xb7,
        0x4d, 0xe6, 0x2a, 0x4d, 0x21, 0x92, 0xea, 0x24, 0x25, 0xd2, 0xc4, 0x0d, 0xde, 0xd3, 0xa2,
        0x40, 0x00, 0x00, 0x00, 0x49, 0xf4, 0x12, 0xec, 0x00, 0x01, 0xae, 0x01, 0xcb, 0x01, 0x00,
        0x00, 0xc3, 0x8e, 0xad, 0x7d, 0x3e, 0x30, 0x0d, 0x8b, 0x02, 0x00, 0x00, 0x00, 0x00, 0x01,
        0x59, 0x5a,
    ];

    async fn gzip(raw: &[u8]) -> Vec<u8> {
        use async_compression::tokio::write::GzipEncoder;
        use tokio::io::AsyncWriteExt as _;

        let mut encoder = GzipEncoder::new(Vec::new());
        encoder.write_all(raw).await.expect("gzip write");
        encoder.shutdown().await.expect("gzip finish");
        encoder.into_inner()
    }

    async fn encoded_index(compression: PackagesCompression) -> Vec<u8> {
        match compression {
            PackagesCompression::Raw => INDEX_RAW.to_vec(),
            PackagesCompression::Gz => gzip(INDEX_RAW).await,
            PackagesCompression::Xz => INDEX_XZ.to_vec(),
        }
    }

    /// How a test hands the reduce its index: hyper's buffered file, or the
    /// bridge's bytes.
    #[derive(Debug, Clone, Copy)]
    enum Via {
        File,
        Bytes,
    }

    async fn index_via(
        via: Via,
        compression: PackagesCompression,
        bytes: Vec<u8>,
    ) -> FetchedPackages {
        match via {
            Via::File => {
                let file = tempfile::tempfile().expect("tempfile");
                let mut file = tokio::fs::File::from_std(file);
                {
                    use tokio::io::{AsyncSeekExt as _, AsyncWriteExt as _};
                    file.write_all(&bytes).await.expect("write index");
                    file.flush().await.expect("flush index");
                    file.rewind().await.expect("rewind index");
                }
                fetched(compression, file, "packages").await
            }
            Via::Bytes => FetchedPackages {
                compression,
                name: "packages".to_owned(),
                len: bytes.len() as u64,
                input: PackagesInput::Bytes(bytes),
            },
        }
    }

    /// Reduce `keys`, structured-pool candidates below `root`, against
    /// `index`; returns the outcome and the candidates left.
    async fn reduce_keys(
        index: FetchedPackages,
        root: &Path,
        keys: &[&str],
    ) -> (Result<(), ReduceError>, HashMap<OsString, SpanClass>) {
        let mirror = structured_mirror("example.com", "debian");
        let mut file_list = cands(keys);
        let mut tally = UnitStats::default();
        let mut ctx = ReduceContext {
            root,
            mirror: &mirror,
            layout: CacheLayout::StructuredPool,
            tally: &mut tally,
            keymap: KeyMapper::Basename,
        };
        let result = reduce_file_list(index, &mut file_list, &mut ctx, BUFFER_SIZE).await;
        (result, file_list)
    }

    /// The decode ladder is one for both inputs: every format reduces the
    /// same candidates whether the index arrives as a file or as bytes,
    /// verifying the referenced deb and keeping it on disk.
    #[tokio::test]
    async fn reduce_file_list_decodes_files_and_bytes_alike() {
        let dir = tempfile::tempdir().expect("tempdir");
        let kept = dir.path().join("kept_1_amd64.deb");
        tokio::fs::write(&kept, KEPT_DEB).await.expect("write deb");

        for compression in [
            PackagesCompression::Raw,
            PackagesCompression::Gz,
            PackagesCompression::Xz,
        ] {
            for via in [Via::File, Via::Bytes] {
                let index = index_via(via, compression, encoded_index(compression).await).await;
                let (result, left) = reduce_keys(
                    index,
                    dir.path(),
                    &[
                        "kept_1_amd64.deb",
                        "nodigest_1_amd64.deb",
                        "unreferenced.deb",
                    ],
                )
                .await;
                assert!(result.is_ok(), "{compression:?} via {via:?}: {result:?}");
                assert_eq!(
                    left.keys().collect::<Vec<_>>(),
                    [OsStr::new("unreferenced.deb")],
                    "{compression:?} via {via:?}"
                );
                assert!(kept.exists(), "a verified deb stays cached");
            }
        }
    }

    /// Once every candidate is referenced the reduce stops reading: a
    /// malformed tail past that point is never decoded, while it still fails
    /// a reduce that has candidates left.
    #[tokio::test]
    async fn reduce_file_list_stops_reading_once_every_candidate_is_referenced() {
        let dir = tempfile::tempdir().expect("tempdir");
        tokio::fs::write(dir.path().join("kept_1_amd64.deb"), KEPT_DEB)
            .await
            .expect("write deb");
        let mut raw = INDEX_RAW.to_vec();
        raw.extend_from_slice(b"Package: \xff\xfe not UTF-8\n\n");

        for via in [Via::File, Via::Bytes] {
            let index = index_via(via, PackagesCompression::Raw, raw.clone()).await;
            let (result, left) = reduce_keys(index, dir.path(), &["kept_1_amd64.deb"]).await;
            assert!(result.is_ok(), "via {via:?}: {result:?}");
            assert!(left.is_empty());

            let index = index_via(via, PackagesCompression::Raw, raw.clone()).await;
            let (result, left) =
                reduce_keys(index, dir.path(), &["kept_1_amd64.deb", "unreferenced.deb"]).await;
            assert!(
                matches!(result, Err(ReduceError::Read { .. })),
                "via {via:?}: {result:?}"
            );
            assert!(left.contains_key(OsStr::new("unreferenced.deb")));
        }
    }

    /// The guards the file path has hold for in-memory bytes: an empty
    /// compressed index, a malformed or bomb-sized stream, and an index past
    /// its compressed cap all fail, an empty raw index is no stanzas.
    #[tokio::test]
    async fn reduce_file_list_guards_in_memory_indexes() {
        let root = Path::new("/nonexistent");
        let keys = ["keep-me.deb"];
        let bytes = |compression, bytes: Vec<u8>| index_via(Via::Bytes, compression, bytes);

        let (result, left) = reduce_keys(
            bytes(PackagesCompression::Raw, Vec::new()).await,
            root,
            &keys,
        )
        .await;
        assert!(result.is_ok(), "{result:?}");
        assert_eq!(left.len(), 1);

        for compression in [PackagesCompression::Gz, PackagesCompression::Xz] {
            let (result, left) =
                reduce_keys(bytes(compression, Vec::new()).await, root, &keys).await;
            assert!(
                matches!(result, Err(ReduceError::ZeroSizeCompressed { .. })),
                "{compression:?}: {result:?}"
            );
            assert_eq!(left.len(), 1);

            let (result, left) = reduce_keys(
                bytes(compression, b"not a compressed stream".to_vec()).await,
                root,
                &keys,
            )
            .await;
            assert!(
                matches!(result, Err(ReduceError::Read { .. })),
                "{compression:?}: {result:?}"
            );
            assert_eq!(left.len(), 1);
        }

        // 4 MiB of newlines gzips to a few KiB, far past the ratio cap.
        let bomb = gzip(&vec![b'\n'; 4 * 1024 * 1024]).await;
        let (result, _) =
            reduce_keys(bytes(PackagesCompression::Gz, bomb).await, root, &keys).await;
        assert!(
            matches!(result, Err(ReduceError::Read { .. })),
            "{result:?}"
        );

        // Zero-filled, so the allocation stays lazy; refused before decoding.
        let oversized =
            vec![0; usize::try_from(MAX_COMPRESSED_PACKAGES_SIZE.get() + 1).expect("fits")];
        let (result, left) =
            reduce_keys(bytes(PackagesCompression::Xz, oversized).await, root, &keys).await;
        assert!(
            matches!(result, Err(ReduceError::TooLarge { .. })),
            "{result:?}"
        );
        assert_eq!(left.len(), 1);
    }
}
